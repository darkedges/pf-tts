package ttsadapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/pingfederate"
	"example.com/workload-agent-identity/pkg/transaction"
)

const TransactionTokenType = "urn:ietf:params:oauth:token-type:txn_token"

var ErrInvalidAdapterConfiguration = errors.New("invalid transaction token adapter configuration")

type StrictTokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (transaction.TxnTokenClaims, error)
}

type CallerIdentity func(state *tls.ConnectionState) (string, error)

type FailureReporter func(stage string)

type Config struct {
	TrustDomain       string
	Scope             string
	EndpointPath      string
	MaximumBodyBytes  int64
	MaximumTokenBytes int
	MaximumExpiresIn  int64
	Exchanger         pingfederate.TokenExchanger
	Verifier          StrictTokenVerifier
	Caller            CallerIdentity
	ReportFailure     FailureReporter
}

type Handler struct{ config Config }

func NewHandler(config Config) (*Handler, error) {
	if strings.TrimSpace(config.TrustDomain) == "" || strings.ToLower(config.TrustDomain) != config.TrustDomain || strings.ContainsAny(config.TrustDomain, "/:@ \t\r\n") || strings.TrimSpace(config.Scope) == "" || strings.ContainsAny(config.Scope, " \t\r\n") || config.EndpointPath == "" || !strings.HasPrefix(config.EndpointPath, "/") || strings.ContainsAny(config.EndpointPath, "?# \t\r\n") || config.MaximumBodyBytes <= 0 || config.MaximumTokenBytes <= 0 || config.MaximumExpiresIn <= 0 || config.Exchanger == nil || config.Verifier == nil || config.Caller == nil {
		return nil, ErrInvalidAdapterConfiguration
	}
	return &Handler{config: config}, nil
}

var exactFields = map[string]struct{}{
	"grant_type": {}, "subject_token": {}, "subject_token_type": {},
	"actor_token": {}, "actor_token_type": {}, "requested_token_type": {},
	"audience": {}, "scope": {},
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost || r.URL.Path != h.config.EndpointPath || r.URL.RawQuery != "" || len(r.Cookies()) != 0 || len(r.Header.Values("Authorization")) != 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(parameters) != 0 {
		writeOAuthError(w, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	caller, err := h.config.Caller(r.TLS)
	if err != nil || strings.TrimSpace(caller) == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.config.MaximumBodyBytes+1))
	if err != nil || int64(len(body)) > h.config.MaximumBodyBytes {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) != len(exactFields) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for name := range exactFields {
		values, ok := form[name]
		if !ok || len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	for name := range form {
		if _, ok := exactFields[name]; !ok {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	if form.Get("grant_type") != pingfederate.TokenExchangeGrantType || form.Get("subject_token_type") != pingfederate.AccessTokenType || form.Get("actor_token_type") != pingfederate.JWTTokenType || form.Get("requested_token_type") != TransactionTokenType || form.Get("audience") != h.config.TrustDomain || form.Get("scope") != h.config.Scope || len(form.Get("subject_token")) > h.config.MaximumTokenBytes || len(form.Get("actor_token")) > h.config.MaximumTokenBytes {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	upstream, err := h.config.Exchanger.Exchange(r.Context(), pingfederate.ExchangeRequest{
		SubjectToken: form.Get("subject_token"), ActorToken: form.Get("actor_token"),
		SubjectTokenType: pingfederate.AccessTokenType, ActorTokenType: pingfederate.JWTTokenType,
		Audience: h.config.TrustDomain, Scope: []string{h.config.Scope},
	})
	if err != nil {
		h.reportFailure("upstream_exchange")
		writeOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	if upstream.AccessToken == "" || len(upstream.AccessToken) > h.config.MaximumTokenBytes || upstream.TokenType != "Bearer" || upstream.IssuedTokenType != pingfederate.AccessTokenType || upstream.ExpiresIn <= 0 || upstream.ExpiresIn > h.config.MaximumExpiresIn || upstream.Scope != "" {
		h.reportFailure("upstream_response")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	claims, err := h.config.Verifier.Verify(r.Context(), upstream.AccessToken)
	if err != nil {
		h.reportFailure("inner_verification")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	if claims.RequestingWorkloadID != caller {
		h.reportFailure("inner_workload_binding")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	if claims.Audience != h.config.TrustDomain {
		h.reportFailure("inner_audience_binding")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	if len(claims.Scope) != 1 || claims.Scope[0] != h.config.Scope {
		h.reportFailure("inner_scope_binding")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	signedLifetime := claims.ExpiresAt.Sub(claims.IssuedAt)
	if signedLifetime <= 0 || signedLifetime > time.Duration(h.config.MaximumExpiresIn)*time.Second || signedLifetime%time.Second != 0 || time.Duration(upstream.ExpiresIn)*time.Second > signedLifetime {
		h.reportFailure("inner_expiry_binding")
		writeOAuthError(w, http.StatusBadGateway, "server_error")
		return
	}
	expiresIn := int64(signedLifetime / time.Second)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int64  `json:"expires_in"`
	}{upstream.AccessToken, TransactionTokenType, "N_A", expiresIn})
}

func (h *Handler) reportFailure(stage string) {
	if h.config.ReportFailure != nil {
		h.config.ReportFailure(stage)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
