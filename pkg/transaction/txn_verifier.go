package transaction

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var ErrTxnTokenVerification = errors.New("transaction token verification failed")

type VerificationKeyResolver interface {
	ResolveVerificationKey(ctx context.Context, keyID string) (any, error)
}

type TxnTokenVerifierConfig struct {
	Mode                   ProfileMode
	Issuer                 string
	TrustDomain            string
	Algorithms             []jose.SignatureAlgorithm
	ClockSkew              time.Duration
	MaximumLifetime        time.Duration
	MaximumTokenBytes      int
	MaximumPayloadBytes    int
	MaximumIdentifierBytes int
	MaximumContextBytes    int
	MaximumScopes          int
	AllowedScopes          map[string]struct{}
	WorkloadAgentBindings  map[string]string
	Keys                   VerificationKeyResolver
	Now                    func() time.Time
}

type TxnTokenVerifier struct {
	config TxnTokenVerifierConfig
	algs   map[string]struct{}
}

func NewTxnTokenVerifier(config TxnTokenVerifierConfig) (*TxnTokenVerifier, error) {
	if config.Mode != ProfileTxnTokenV11 || config.Mode.Validate() != nil || strings.TrimSpace(config.Issuer) == "" || !validTrustDomain(config.TrustDomain) || len(config.Algorithms) == 0 || config.ClockSkew < 0 || config.MaximumLifetime <= 0 || config.MaximumTokenBytes <= 0 || config.MaximumPayloadBytes <= 0 || config.MaximumIdentifierBytes <= 0 || config.MaximumContextBytes <= 0 || config.MaximumScopes <= 0 || len(config.AllowedScopes) == 0 || len(config.WorkloadAgentBindings) == 0 || config.Keys == nil {
		return nil, txnVerificationError("invalid verifier configuration")
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.Fragment != "" {
		return nil, txnVerificationError("invalid verifier configuration")
	}
	algs := make(map[string]struct{}, len(config.Algorithms))
	for _, alg := range config.Algorithms {
		if strings.TrimSpace(string(alg)) == "" {
			return nil, txnVerificationError("invalid verifier configuration")
		}
		algs[string(alg)] = struct{}{}
	}
	for scope := range config.AllowedScopes {
		if !boundedValue(scope, config.MaximumIdentifierBytes) || strings.ContainsAny(scope, " \t\r\n") {
			return nil, txnVerificationError("invalid verifier configuration")
		}
	}
	for workload, agent := range config.WorkloadAgentBindings {
		if !validSPIFFEID(workload, config.TrustDomain) || !boundedValue(agent, config.MaximumIdentifierBytes) {
			return nil, txnVerificationError("invalid verifier configuration")
		}
	}
	allowedScopes := make(map[string]struct{}, len(config.AllowedScopes))
	for scope := range config.AllowedScopes {
		allowedScopes[scope] = struct{}{}
	}
	bindings := make(map[string]string, len(config.WorkloadAgentBindings))
	for workload, agent := range config.WorkloadAgentBindings {
		bindings[workload] = agent
	}
	config.Algorithms = append([]jose.SignatureAlgorithm(nil), config.Algorithms...)
	config.AllowedScopes = allowedScopes
	config.WorkloadAgentBindings = bindings
	if config.Now == nil {
		config.Now = time.Now
	}
	return &TxnTokenVerifier{config: config, algs: algs}, nil
}

type txnWireClaims struct {
	Issuer               string                    `json:"iss"`
	Subject              string                    `json:"sub"`
	Audience             string                    `json:"aud"`
	IssuedAt             int64                     `json:"iat"`
	ExpiresAt            int64                     `json:"exp"`
	TransactionID        string                    `json:"txn"`
	Scope                string                    `json:"scope"`
	RequestingWorkloadID string                    `json:"req_wl"`
	TransactionContext   txnWireTransactionContext `json:"tctx"`
	RequestContext       *txnWireRequestContext    `json:"rctx,omitempty"`
	JWTID                string                    `json:"jti,omitempty"`
}

type txnWireTransactionContext struct {
	WAI txnWireWAIContext `json:"wai"`
}

type txnWireWAIContext struct {
	Version int             `json:"version"`
	Agent   txnWireAgentCtx `json:"agent"`
	Target  string          `json:"target"`
	Tool    string          `json:"tool"`
}

type txnWireAgentCtx struct {
	ID         string `json:"id"`
	InstanceID string `json:"instance_id"`
	WorkloadID string `json:"workload_id"`
}

type txnWireRequestContext struct {
	AuthenticationMethod string `json:"authn"`
}

func (v *TxnTokenVerifier) Verify(ctx context.Context, rawToken string) (TxnTokenClaims, error) {
	if err := ctx.Err(); err != nil {
		return TxnTokenClaims{}, txnVerificationError("verification cancelled")
	}
	if len(rawToken) == 0 || len(rawToken) > v.config.MaximumTokenBytes || strings.Count(rawToken, ".") != 2 || strings.TrimSpace(rawToken) != rawToken {
		return TxnTokenClaims{}, txnVerificationError("invalid compact token")
	}
	parts := strings.Split(rawToken, ".")
	protectedJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(protectedJSON) == 0 || len(protectedJSON) > v.config.MaximumContextBytes || rejectDuplicateJSONKeys(protectedJSON) != nil {
		return TxnTokenClaims{}, txnVerificationError("invalid protected header JSON")
	}
	signed, err := jose.ParseSigned(rawToken, v.config.Algorithms)
	if err != nil || len(signed.Signatures) != 1 {
		return TxnTokenClaims{}, txnVerificationError("invalid signed token")
	}
	sig := signed.Signatures[0]
	if !emptyJOSEHeader(sig.Unprotected) || sig.Protected.KeyID == "" || sig.Protected.Algorithm == "" || sig.Protected.ExtraHeaders[jose.HeaderType] != TxnTokenJOSEType {
		return TxnTokenClaims{}, txnVerificationError("invalid protected header")
	}
	if len(sig.Protected.ExtraHeaders) != 1 {
		return TxnTokenClaims{}, txnVerificationError("unsupported protected header")
	}
	if _, ok := v.algs[sig.Protected.Algorithm]; !ok {
		return TxnTokenClaims{}, txnVerificationError("disallowed algorithm")
	}
	if !boundedValue(sig.Protected.KeyID, v.config.MaximumIdentifierBytes) {
		return TxnTokenClaims{}, txnVerificationError("invalid key ID")
	}
	key, err := v.config.Keys.ResolveVerificationKey(ctx, sig.Protected.KeyID)
	if err != nil || key == nil {
		return TxnTokenClaims{}, txnVerificationError("unknown or ambiguous key ID")
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return TxnTokenClaims{}, txnVerificationError("signature validation failed")
	}
	if len(payload) == 0 || len(payload) > v.config.MaximumPayloadBytes || rejectDuplicateJSONKeys(payload) != nil {
		return TxnTokenClaims{}, txnVerificationError("invalid claims JSON")
	}
	var wire txnWireClaims
	if err := json.Unmarshal(payload, &wire); err != nil {
		return TxnTokenClaims{}, txnVerificationError("invalid claims schema")
	}
	if err := decodeStrictLocalContexts(payload, &wire); err != nil {
		return TxnTokenClaims{}, txnVerificationError("invalid local context schema")
	}
	if err := v.validateWire(wire); err != nil {
		return TxnTokenClaims{}, err
	}
	return TxnTokenClaims{
		Issuer: wire.Issuer, Subject: wire.Subject, Audience: wire.Audience,
		TransactionID: wire.TransactionID, Scope: strings.Fields(wire.Scope),
		RequestingWorkloadID: wire.RequestingWorkloadID, JWTID: wire.JWTID,
		IssuedAt: time.Unix(wire.IssuedAt, 0), ExpiresAt: time.Unix(wire.ExpiresAt, 0),
		TransactionContext: TransactionContext{WAI: WAITransactionContext{
			Version: wire.TransactionContext.WAI.Version,
			Agent:   WAIAgentContext{ID: wire.TransactionContext.WAI.Agent.ID, InstanceID: wire.TransactionContext.WAI.Agent.InstanceID, WorkloadID: wire.TransactionContext.WAI.Agent.WorkloadID},
			Target:  wire.TransactionContext.WAI.Target, Tool: wire.TransactionContext.WAI.Tool,
		}},
		RequestContext: mapRequestContext(wire.RequestContext),
	}, nil
}

func (v *TxnTokenVerifier) validateWire(w txnWireClaims) error {
	maxID := v.config.MaximumIdentifierBytes
	if w.Issuer != v.config.Issuer || w.Audience != v.config.TrustDomain || !boundedValue(w.Subject, maxID) || !boundedValue(w.TransactionID, maxID) || (w.JWTID != "" && !boundedValue(w.JWTID, maxID)) {
		return txnVerificationError("invalid standard identity claims")
	}
	now := v.config.Now()
	iat, exp := time.Unix(w.IssuedAt, 0), time.Unix(w.ExpiresAt, 0)
	if w.IssuedAt <= 0 || w.ExpiresAt <= 0 || exp.Before(now.Add(-v.config.ClockSkew)) || iat.After(now.Add(v.config.ClockSkew)) || !exp.After(iat) || exp.Sub(iat) > v.config.MaximumLifetime {
		return txnVerificationError("invalid token time window")
	}
	scopes := strings.Fields(w.Scope)
	if len(scopes) == 0 || len(scopes) > v.config.MaximumScopes || strings.Join(scopes, " ") != w.Scope {
		return txnVerificationError("invalid scope")
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, allowed := v.config.AllowedScopes[scope]; !allowed {
			return txnVerificationError("scope is not allowed")
		}
		if _, duplicate := seen[scope]; duplicate {
			return txnVerificationError("duplicate scope")
		}
		seen[scope] = struct{}{}
	}
	wai := w.TransactionContext.WAI
	contextJSON, err := json.Marshal(w.TransactionContext)
	if err != nil || len(contextJSON) > v.config.MaximumContextBytes {
		return txnVerificationError("transaction context is too large")
	}
	if wai.Version != 1 || !validSPIFFEID(w.RequestingWorkloadID, v.config.TrustDomain) || wai.Agent.WorkloadID != w.RequestingWorkloadID || !boundedValue(wai.Agent.ID, maxID) || !boundedValue(wai.Agent.InstanceID, maxID) || !boundedValue(wai.Target, maxID) || !boundedValue(wai.Tool, maxID) {
		return txnVerificationError("invalid local transaction context")
	}
	boundAgent, ok := v.config.WorkloadAgentBindings[w.RequestingWorkloadID]
	if !ok || boundAgent != wai.Agent.ID {
		return txnVerificationError("requesting workload binding mismatch")
	}
	if w.RequestContext != nil {
		requestContextJSON, err := json.Marshal(w.RequestContext)
		if err != nil || len(requestContextJSON) > v.config.MaximumContextBytes || !boundedValue(w.RequestContext.AuthenticationMethod, maxID) {
			return txnVerificationError("invalid request context")
		}
	}
	return nil
}

func mapRequestContext(w *txnWireRequestContext) *RequestContext {
	if w == nil {
		return nil
	}
	return &RequestContext{AuthenticationMethod: w.AuthenticationMethod}
}

func decodeStrictLocalContexts(payload []byte, wire *txnWireClaims) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return err
	}
	tctx, ok := top["tctx"]
	if !ok {
		return errors.New("missing transaction context")
	}
	if err := strictJSONDecode(tctx, &wire.TransactionContext); err != nil {
		return err
	}
	if rctx, ok := top["rctx"]; ok {
		var decoded txnWireRequestContext
		if err := strictJSONDecode(rctx, &decoded); err != nil {
			return err
		}
		wire.RequestContext = &decoded
	}
	return nil
}

func strictJSONDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validTrustDomain(value string) bool {
	return value != "" && !strings.ContainsAny(value, "/:@ \t\r\n") && strings.ToLower(value) == value
}

func validSPIFFEID(value, trustDomain string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "spiffe" && u.Host == trustDomain && u.Path != "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func boundedValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func emptyJOSEHeader(h jose.Header) bool {
	return h.KeyID == "" && h.JSONWebKey == nil && h.Algorithm == "" && h.Nonce == "" && len(h.ExtraHeaders) == 0
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func txnVerificationError(reason string) error {
	return fmt.Errorf("%w: %s", ErrTxnTokenVerification, reason)
}
