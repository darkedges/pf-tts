package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/middleware"
	"example.com/workload-agent-identity/pkg/transaction"
)

const rawToken = "raw-transaction-token-must-not-appear"

type verifier struct{ claims transaction.Claims }

func (v verifier) Verify(_ context.Context, raw, audience string) (transaction.Claims, error) {
	if raw != rawToken {
		return transaction.Claims{}, errors.New("bad token")
	}
	if v.claims.ExpiresAt.Before(time.Now()) {
		return transaction.Claims{}, errors.New("expired")
	}
	found := false
	for _, candidate := range v.claims.Audience {
		found = found || candidate == audience
	}
	if !found {
		return transaction.Claims{}, errors.New("wrong audience")
	}
	return v.claims, nil
}

type callerPolicy struct {
	caller       string
	bindOriginal bool
}

func (p callerPolicy) Authorize(c transaction.Claims, caller string) error {
	if caller != p.caller {
		return errors.New("wrong caller")
	}
	if p.bindOriginal && (c.WorkloadID != caller || c.AgentID != "urn:agent:demo") {
		return errors.New("forged binding")
	}
	return nil
}

func state(t *testing.T, id string) *tls.ConnectionState {
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{URIs: []*url.URL{u}}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
}

func claims() transaction.Claims {
	now := time.Now()
	return transaction.Claims{Issuer: "https://pf", Subject: "user-123", Audience: []string{"urn:wai:mcp-gateway"}, JWTID: "jti-123", AgentID: "urn:agent:demo", AgentInstanceID: "instance-123", WorkloadID: "spiffe://example.org/agent/demo", TransactionID: "transaction-123", Purpose: "system.whoami", Scope: []string{"mcp:invoke"}, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Second)}
}

func invoke(t *testing.T, c transaction.Claims, hop string, auth string) *httptest.ResponseRecorder {
	t.Helper()
	allowed := map[string]string{"gateway": "spiffe://example.org/agent/demo", "mcp": "spiffe://example.org/gateway/mcp", "api": "spiffe://example.org/mcp/demo"}
	m := middleware.Middleware{Verifier: verifier{c}, Audience: "urn:wai:mcp-gateway", Callers: callerPolicy{caller: allowed[hop], bindOriginal: hop == "gateway"}}
	req := httptest.NewRequest(http.MethodPost, "https://"+hop+"/", nil)
	req.Header.Set("Authorization", auth)
	req.TLS = state(t, allowed[hop])
	rr := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := identity.FromContext(r.Context())
		if !ok || got.Transaction.ID != "transaction-123" {
			t.Fatal("transaction identity was not preserved")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	return rr
}

func TestValidTransactionIDIsConsistentAcrossAllHops(t *testing.T) {
	for _, hop := range []string{"gateway", "mcp", "api"} {
		if status := invoke(t, claims(), hop, "Bearer "+rawToken).Code; status != http.StatusNoContent {
			t.Fatalf("%s status=%d", hop, status)
		}
	}
}

func TestEndToEndFailuresAreClosed(t *testing.T) {
	tests := []struct {
		name, hop, auth string
		mutate          func(*transaction.Claims)
		want            int
	}{
		{"forged AgentID", "gateway", "Bearer " + rawToken, func(c *transaction.Claims) { c.AgentID = "urn:agent:admin" }, http.StatusForbidden},
		{"wrong workload", "gateway", "Bearer " + rawToken, func(c *transaction.Claims) { c.WorkloadID = "spiffe://example.org/agent/other" }, http.StatusForbidden},
		{"wrong audience", "gateway", "Bearer " + rawToken, func(c *transaction.Claims) { c.Audience = []string{"other"} }, http.StatusUnauthorized},
		{"expired", "gateway", "Bearer " + rawToken, func(c *transaction.Claims) { c.ExpiresAt = time.Now().Add(-time.Second) }, http.StatusUnauthorized},
		{"direct agent to API", "api", "Bearer " + rawToken, func(*transaction.Claims) {}, http.StatusForbidden},
		{"missing token", "gateway", "", func(*transaction.Claims) {}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := claims()
			tt.mutate(&c)
			rr := invokeWithCaller(t, c, tt.hop, tt.auth, map[bool]string{true: "spiffe://example.org/agent/demo", false: ""}[tt.name == "direct agent to API"])
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func invokeWithCaller(t *testing.T, c transaction.Claims, hop, auth, override string) *httptest.ResponseRecorder {
	allowed := map[string]string{"gateway": "spiffe://example.org/agent/demo", "api": "spiffe://example.org/mcp/demo"}
	caller := allowed[hop]
	if override != "" {
		caller = override
	}
	m := middleware.Middleware{Verifier: verifier{c}, Audience: "urn:wai:mcp-gateway", Callers: callerPolicy{caller: allowed[hop], bindOriginal: hop == "gateway"}}
	req := httptest.NewRequest(http.MethodPost, "https://"+hop+"/", nil)
	req.Header.Set("Authorization", auth)
	req.TLS = state(t, caller)
	rr := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("denied request reached handler") })).ServeHTTP(rr, req)
	return rr
}

func TestUnapprovedTargetAndLogsDoNotExposeToken(t *testing.T) {
	var log bytes.Buffer
	sink := audit.NewJSONSink(&log)
	_ = sink.Write(audit.Event{Type: audit.MCPToolDenied, TransactionID: "transaction-123", Target: "unapproved", Decision: "deny", ReasonCode: "target_not_allowed"})
	if strings.Contains(log.String(), rawToken) || strings.Contains(strings.ToLower(log.String()), "bearer") {
		t.Fatal("audit log leaked bearer material")
	}
}
