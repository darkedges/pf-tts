package ttsadapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/pingfederate"
	"example.com/workload-agent-identity/pkg/transaction"
)

type rejectingAuditSink struct{}

func (rejectingAuditSink) Write(audit.Event) error { return errors.New("collector unavailable") }

type fakeExchanger struct {
	response pingfederate.ExchangeResponse
	err      error
	request  pingfederate.ExchangeRequest
}

func (f *fakeExchanger) Exchange(_ context.Context, request pingfederate.ExchangeRequest) (pingfederate.ExchangeResponse, error) {
	f.request = request
	return f.response, f.err
}

type fakeVerifier struct {
	claims transaction.TxnTokenClaims
	err    error
	raw    string
}

func (f *fakeVerifier) Verify(_ context.Context, raw string) (transaction.TxnTokenClaims, error) {
	f.raw = raw
	return f.claims, f.err
}

func validHandler(t *testing.T) (*Handler, *fakeExchanger, *fakeVerifier) {
	t.Helper()
	exchanger := &fakeExchanger{response: pingfederate.ExchangeResponse{
		AccessToken: "signed-by-pingfederate", TokenType: "Bearer",
		IssuedTokenType: pingfederate.AccessTokenType, ExpiresIn: 20,
	}}
	verifier := &fakeVerifier{claims: transaction.TxnTokenClaims{
		Audience: "example.org", Scope: []string{"mcp.system.whoami"},
		RequestingWorkloadID: "spiffe://example.org/agent/demo",
		IssuedAt:             time.Unix(1_800_000_000, 0), ExpiresAt: time.Unix(1_800_000_020, 0),
	}}
	handler, err := NewHandler(Config{
		TrustDomain: "example.org", Scope: "mcp.system.whoami", EndpointPath: "/as/token.oauth2", MaximumBodyBytes: 4096,
		MaximumTokenBytes: 2048, MaximumExpiresIn: 60, Exchanger: exchanger, Verifier: verifier,
		Caller: func(*tls.ConnectionState) (string, error) { return "spiffe://example.org/agent/demo", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, exchanger, verifier
}

func validForm() url.Values {
	return url.Values{
		"grant_type": {pingfederate.TokenExchangeGrantType}, "subject_token": {"subject-secret"},
		"subject_token_type": {pingfederate.AccessTokenType}, "actor_token": {"actor-secret"},
		"actor_token_type": {pingfederate.JWTTokenType}, "requested_token_type": {TransactionTokenType},
		"audience": {"example.org"}, "scope": {"mcp.system.whoami"},
	}
}

func requestFor(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "https://tts.example/as/token.oauth2", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = &tls.ConnectionState{}
	return req
}

func TestHandlerTranslatesOnlyOuterProtocolAndPreservesSignedToken(t *testing.T) {
	handler, exchanger, verifier := validHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestFor(validForm()))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["access_token"] != "signed-by-pingfederate" || verifier.raw != "signed-by-pingfederate" {
		t.Fatal("adapter mutated or replaced the PingFederate-signed token")
	}
	if response["issued_token_type"] != TransactionTokenType || response["token_type"] != "N_A" || len(response) != 4 {
		t.Fatalf("unexpected outer response: %#v", response)
	}
	if exchanger.request.SubjectToken != "subject-secret" || exchanger.request.ActorToken != "actor-secret" || exchanger.request.Audience != "example.org" || len(exchanger.request.Scope) != 1 || exchanger.request.Scope[0] != "mcp.system.whoami" {
		t.Fatalf("unexpected translated upstream request: %#v", exchanger.request)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatal("successful token response must prohibit caching")
	}
}

func TestHandlerRejectsMalformedAndAmbiguousRequests(t *testing.T) {
	tests := map[string]func(*http.Request){
		"wrong method":  func(r *http.Request) { r.Method = http.MethodGet },
		"wrong path":    func(r *http.Request) { r.URL.Path = "/token" },
		"query":         func(r *http.Request) { r.URL.RawQuery = "token=secret" },
		"cookie":        func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "token", Value: "secret"}) },
		"authorization": func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") },
		"wrong media":   func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		"media parameter": func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		},
		"duplicate actor": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(validForm().Encode() + "&actor_token=other"))
		},
		"missing actor": func(r *http.Request) {
			f := validForm()
			f.Del("actor_token")
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"unknown field": func(r *http.Request) {
			f := validForm()
			f.Set("agent_id", "forged")
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"wrong requested type": func(r *http.Request) {
			f := validForm()
			f.Set("requested_token_type", pingfederate.AccessTokenType)
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"wrong subject type": func(r *http.Request) {
			f := validForm()
			f.Set("subject_token_type", "urn:example:refresh")
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"wrong actor type": func(r *http.Request) {
			f := validForm()
			f.Set("actor_token_type", pingfederate.AccessTokenType)
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"wrong audience": func(r *http.Request) {
			f := validForm()
			f.Set("audience", "other.org")
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"wrong scope": func(r *http.Request) {
			f := validForm()
			f.Set("scope", "admin.all")
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"oversized actor": func(r *http.Request) {
			f := validForm()
			f.Set("actor_token", strings.Repeat("x", 2049))
			r.Body = io.NopCloser(strings.NewReader(f.Encode()))
		},
		"oversized body": func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 4097))) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			handler, exchanger, _ := validHandler(t)
			req := requestFor(validForm())
			mutate(req)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code < 400 || exchanger.request.SubjectToken != "" {
				t.Fatalf("malformed request reached upstream: status=%d", recorder.Code)
			}
			assertNoCredentialLeak(t, recorder.Body.String())
		})
	}
}

func TestHandlerRejectsUntrustedUpstreamAndCallerResults(t *testing.T) {
	tests := map[string]func(*fakeExchanger, *fakeVerifier, *Handler){
		"upstream failure":   func(e *fakeExchanger, _ *fakeVerifier, _ *Handler) { e.err = errors.New("subject-secret actor-secret") },
		"wrong outer type":   func(e *fakeExchanger, _ *fakeVerifier, _ *Handler) { e.response.TokenType = "N_A" },
		"refresh-like scope": func(e *fakeExchanger, _ *fakeVerifier, _ *Handler) { e.response.Scope = "mcp.system.whoami" },
		"excess expiry":      func(e *fakeExchanger, _ *fakeVerifier, _ *Handler) { e.response.ExpiresIn = 61 },
		"invalid token":      func(_ *fakeExchanger, v *fakeVerifier, _ *Handler) { v.err = errors.New("signed-by-pingfederate") },
		"wrong workload": func(_ *fakeExchanger, v *fakeVerifier, _ *Handler) {
			v.claims.RequestingWorkloadID = "spiffe://example.org/agent/other"
		},
		"wrong verified scope": func(_ *fakeExchanger, v *fakeVerifier, _ *Handler) { v.claims.Scope = []string{"admin.all"} },
		"expiry inconsistency": func(_ *fakeExchanger, v *fakeVerifier, _ *Handler) {
			v.claims.ExpiresAt = v.claims.IssuedAt.Add(19 * time.Second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			handler, exchanger, verifier := validHandler(t)
			mutate(exchanger, verifier, handler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, requestFor(validForm()))
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			assertNoCredentialLeak(t, recorder.Body.String())
		})
	}
}

func TestHandlerUsesVerifiedSignedLifetimeWhenUpstreamHintIsShorter(t *testing.T) {
	handler, exchanger, _ := validHandler(t)
	exchanger.response.ExpiresIn = 19
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestFor(validForm()))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["expires_in"] != float64(20) {
		t.Fatalf("expires_in=%v, want signed lifetime 20", response["expires_in"])
	}
}

func TestHandlerRejectsIssuanceWhenStrictAuditCannotRecordVerifiedToken(t *testing.T) {
	handler, _, verifier := validHandler(t)
	verifier.claims.Issuer = "https://issuer.example"
	verifier.claims.JWTID = "jti-1"
	verifier.claims.Subject = "user-1"
	verifier.claims.TransactionID = "txn-1"
	verifier.claims.TransactionContext.WAI.Agent.ID = "urn:agent:demo"
	verifier.claims.TransactionContext.WAI.Agent.InstanceID = "instance-1"
	verifier.claims.TransactionContext.WAI.Agent.WorkloadID = "spiffe://example.org/agent/demo"
	verifier.claims.TransactionContext.WAI.Target = "demo"
	verifier.claims.TransactionContext.WAI.Tool = "system.whoami"
	handler.config.Audit = rejectingAuditSink{}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestFor(validForm()))
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "signed-by-pingfederate") {
		t.Fatalf("unaudited token issuance was not rejected safely: status=%d", recorder.Code)
	}
}

func TestHandlerRejectsMissingAuthenticatedCallerAndInvalidConfiguration(t *testing.T) {
	handler, _, _ := validHandler(t)
	handler.config.Caller = func(*tls.ConnectionState) (string, error) { return "", errors.New("ambiguous peer") }
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestFor(validForm()))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", recorder.Code)
	}
	if _, err := NewHandler(Config{}); !errors.Is(err, ErrInvalidAdapterConfiguration) {
		t.Fatalf("invalid configuration accepted: %v", err)
	}
}

func assertNoCredentialLeak(t *testing.T, value string) {
	t.Helper()
	for _, secret := range []string{"subject-secret", "actor-secret", "signed-by-pingfederate", "Bearer secret"} {
		if strings.Contains(value, secret) {
			t.Fatalf("response leaked credential %q", secret)
		}
	}
	if strings.Contains(value, "error_description") {
		t.Fatal("response emitted a prohibited OAuth error description")
	}
}
