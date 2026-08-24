package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/transaction"
)

const strictTransportToken = "header.payload.signature"

type fakeStrictVerifier struct {
	claims transaction.TxnTokenClaims
	err    error
	raw    string
}

func (v *fakeStrictVerifier) Verify(_ context.Context, raw string) (transaction.TxnTokenClaims, error) {
	v.raw = raw
	return v.claims, v.err
}

func validStrictClaims() transaction.TxnTokenClaims {
	now := time.Now().UTC().Truncate(time.Second)
	return transaction.TxnTokenClaims{
		Issuer: "https://pf.example/tts", Subject: "user", Audience: "example.org", TransactionID: "txn",
		Scope: []string{"mcp.system.whoami"}, RequestingWorkloadID: "spiffe://example.org/agent/demo",
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
		TransactionContext: transaction.TransactionContext{WAI: transaction.WAITransactionContext{
			Version: 1, Target: "demo", Tool: "system.whoami",
			Agent: transaction.WAIAgentContext{ID: "urn:agent:demo", InstanceID: "instance", WorkloadID: "spiffe://example.org/agent/demo"},
		}},
	}
}

func newStrictRequest(t *testing.T) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	request.Header.Set(transaction.TxnTokenHeader, strictTransportToken)
	request.TLS = tlsState(t, "spiffe://example.org/agent/demo")
	return request
}

func newStrictMiddleware(t *testing.T, verifier *fakeStrictVerifier, callers map[string]struct{}, sink *recordingAudit) *StrictTxnMiddleware {
	t.Helper()
	config := StrictTxnMiddlewareConfig{Verifier: verifier, MaximumTokenBytes: 1024, AllowedCallers: callers, Service: "gateway"}
	if sink != nil {
		config.Audit = sink
	}
	middleware, err := NewStrictTxnMiddleware(config)
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

func TestStrictTxnMiddlewarePlacesOnlyVerifiedContext(t *testing.T) {
	verifier := &fakeStrictVerifier{claims: validStrictClaims()}
	middleware := newStrictMiddleware(t, verifier, map[string]struct{}{"spiffe://example.org/agent/demo": {}}, nil)
	recorder := httptest.NewRecorder()
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := identity.FromContext(r.Context())
		route, routeOK := VerifiedSignedRoute(r.Context())
		raw, rawOK := VerifiedTransactionToken(r.Context())
		evidence, evidenceOK := VerifiedTransactionTokenEvidence(r.Context())
		if !ok || !routeOK || !rawOK || !evidenceOK || value.User.ID != "user" || value.Agent.ID != "urn:agent:demo" || value.OriginalWorkload.SPIFFEID != "spiffe://example.org/agent/demo" || route.Target != "demo" || route.Tool != "system.whoami" || raw != strictTransportToken || evidence.Kind != "txn_token" {
			t.Fatal("strict verified context was incomplete")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, newStrictRequest(t))
	if recorder.Code != http.StatusNoContent || verifier.raw != strictTransportToken {
		t.Fatalf("status=%d verifier.raw=%q", recorder.Code, verifier.raw)
	}
}

func TestStrictTxnMiddlewareFailsClosed(t *testing.T) {
	tests := map[string]struct {
		prepare func(*http.Request, *fakeStrictVerifier)
		want    int
	}{
		"legacy bearer coexistence": {func(r *http.Request, _ *fakeStrictVerifier) { r.Header.Set("Authorization", "Bearer legacy") }, http.StatusUnauthorized},
		"bad signature":             {func(_ *http.Request, v *fakeStrictVerifier) { v.err = errors.New("bad signature secret") }, http.StatusUnauthorized},
		"missing caller":            {func(r *http.Request, _ *fakeStrictVerifier) { r.TLS = nil }, http.StatusForbidden},
		"ambiguous caller": {func(r *http.Request, _ *fakeStrictVerifier) {
			r.TLS = tlsState(t, "spiffe://example.org/agent/demo", "spiffe://example.org/agent/other")
		}, http.StatusForbidden},
		"wrong caller":           {func(r *http.Request, _ *fakeStrictVerifier) { r.TLS = tlsState(t, "spiffe://example.org/agent/other") }, http.StatusForbidden},
		"invalid typed identity": {func(_ *http.Request, v *fakeStrictVerifier) { v.claims.TransactionContext.WAI.Agent.InstanceID = "" }, http.StatusUnauthorized},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			verifier := &fakeStrictVerifier{claims: validStrictClaims()}
			middleware := newStrictMiddleware(t, verifier, map[string]struct{}{"spiffe://example.org/agent/demo": {}}, nil)
			request := newStrictRequest(t)
			test.prepare(request, verifier)
			recorder := httptest.NewRecorder()
			middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("rejected request reached handler") })).ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status=%d want=%d", recorder.Code, test.want)
			}
		})
	}
}

func TestStrictTxnMiddlewareCopiesCallerPolicyAndFailsClosedOnAudit(t *testing.T) {
	allowed := map[string]struct{}{"spiffe://example.org/agent/demo": {}}
	sink := &recordingAudit{err: errors.New("unavailable")}
	middleware := newStrictMiddleware(t, &fakeStrictVerifier{claims: validStrictClaims()}, allowed, sink)
	delete(allowed, "spiffe://example.org/agent/demo")
	allowed["spiffe://example.org/agent/other"] = struct{}{}
	recorder := httptest.NewRecorder()
	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran after audit failure") })).ServeHTTP(recorder, newStrictRequest(t))
	if recorder.Code != http.StatusInternalServerError || sink.event.Token == nil || sink.event.Token.Kind != "txn_token" {
		t.Fatalf("audit failure was not fail-closed: status=%d event=%+v", recorder.Code, sink.event)
	}
}

func TestStrictTxnMiddlewareRejectsInvalidConfiguration(t *testing.T) {
	base := StrictTxnMiddlewareConfig{Verifier: &fakeStrictVerifier{claims: validStrictClaims()}, MaximumTokenBytes: 1024, AllowedCallers: map[string]struct{}{"spiffe://example.org/agent/demo": {}}, Service: "gateway"}
	tests := []func(*StrictTxnMiddlewareConfig){
		func(c *StrictTxnMiddlewareConfig) { c.Verifier = nil },
		func(c *StrictTxnMiddlewareConfig) { c.MaximumTokenBytes = 0 },
		func(c *StrictTxnMiddlewareConfig) { c.AllowedCallers = nil },
		func(c *StrictTxnMiddlewareConfig) { c.AllowedCallers = map[string]struct{}{"not-spiffe": {}} },
		func(c *StrictTxnMiddlewareConfig) { c.Service = " " },
	}
	for i, mutate := range tests {
		config := base
		mutate(&config)
		if _, err := NewStrictTxnMiddleware(config); err == nil {
			t.Fatalf("invalid configuration %d accepted", i)
		}
	}
}
