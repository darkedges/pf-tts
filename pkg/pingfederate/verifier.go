package pingfederate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/transaction"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ErrTokenVerification = errors.New("transaction token verification failed")

type VerifierConfig struct {
	Issuer, JWKSURL string
	Algorithms      []jose.SignatureAlgorithm
	ClockSkew       time.Duration
	HTTPClient      *http.Client
	Now             func() time.Time
}
type JWTVerifier struct{ config VerifierConfig }

func NewJWTVerifier(config VerifierConfig) (*JWTVerifier, error) {
	issuer, e1 := url.Parse(config.Issuer)
	jwks, e2 := url.Parse(config.JWKSURL)
	if e1 != nil || issuer.Scheme != "https" || issuer.Host == "" || e2 != nil || jwks.Scheme != "https" || jwks.Host == "" || len(config.Algorithms) == 0 || config.HTTPClient == nil || config.HTTPClient.Timeout <= 0 || config.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: invalid verifier configuration", ErrTokenVerification)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &JWTVerifier{config: config}, nil
}

type wireClaims struct {
	jwt.Claims
	AgentID         string `json:"agent_id"`
	AgentInstanceID string `json:"agent_instance_id"`
	WorkloadID      string `json:"workload_id"`
	TransactionID   string `json:"transaction_id"`
	Purpose         string `json:"transaction_purpose"`
	Scope           string `json:"scope"`
}

func (v *JWTVerifier) Verify(ctx context.Context, rawToken, requiredAudience string) (transaction.Claims, error) {
	if strings.TrimSpace(rawToken) == "" || strings.TrimSpace(requiredAudience) == "" {
		return transaction.Claims{}, verificationError("token and audience are required")
	}
	token, err := jwt.ParseSigned(rawToken, v.config.Algorithms)
	if err != nil {
		return transaction.Claims{}, verificationError("token parse failed")
	}
	if len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return transaction.Claims{}, verificationError("missing or ambiguous key ID")
	}
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return transaction.Claims{}, err
	}
	matches := keys.Key(token.Headers[0].KeyID)
	if len(matches) != 1 {
		return transaction.Claims{}, verificationError("unknown or ambiguous key ID")
	}
	var claims wireClaims
	if err := token.Claims(matches[0].Key, &claims); err != nil {
		return transaction.Claims{}, verificationError("signature validation failed")
	}
	now := v.config.Now()
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.config.Issuer, AnyAudience: jwt.Audience{requiredAudience}, Time: now}, v.config.ClockSkew); err != nil {
		return transaction.Claims{}, verificationError("standard claim validation failed")
	}
	result := transaction.Claims{Issuer: claims.Issuer, Subject: claims.Subject, Audience: []string(claims.Audience), JWTID: claims.ID, AgentID: claims.AgentID, AgentInstanceID: claims.AgentInstanceID, WorkloadID: claims.WorkloadID, TransactionID: claims.TransactionID, Purpose: claims.Purpose, Scope: strings.Fields(claims.Scope)}
	if claims.IssuedAt != nil {
		result.IssuedAt = claims.IssuedAt.Time()
	}
	if claims.NotBefore != nil {
		result.NotBefore = claims.NotBefore.Time()
	}
	if claims.Expiry != nil {
		result.ExpiresAt = claims.Expiry.Time()
	}
	if err := result.Validate(now, v.config.ClockSkew); err != nil {
		return transaction.Claims{}, verificationError("required transaction claim validation failed")
	}
	return result, nil
}

func (v *JWTVerifier) fetchKeys(ctx context.Context) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, verificationError("JWKS request failed")
	}
	resp, err := v.config.HTTPClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, verificationError("JWKS request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, verificationError("JWKS endpoint rejected request")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return jose.JSONWebKeySet{}, verificationError("JWKS read failed")
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(body, &keys) != nil || len(keys.Keys) == 0 {
		return jose.JSONWebKeySet{}, verificationError("invalid JWKS response")
	}
	return keys, nil
}

func verificationError(reason string) error {
	return fmt.Errorf("%w: %s", ErrTokenVerification, reason)
}
