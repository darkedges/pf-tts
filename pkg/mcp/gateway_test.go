package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/identity"
)

func TestGatewayRoutesAllowedToolAndPreservesToken(t *testing.T) {
	down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer immutable-token" {
			t.Error("token not preserved")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer down.Close()
	u, _ := url.Parse(down.URL)
	down.Client().Timeout = time.Second
	g, err := NewGateway(down.Client(), []Target{{Name: "demo", URL: u, Tools: map[string]struct{}{"customer.get": {}}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "customer.get")
	req.Header.Set("Authorization", "Bearer immutable-token")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
}

type testAuthorizer struct{ allow bool }

func (a testAuthorizer) Authorize(context.Context, identity.RequestIdentityContext, string, string) error {
	if !a.allow {
		return ErrRouteDenied
	}
	return nil
}

func TestGatewayAuthorizationRequiresVerifiedContextAndPolicyDecision(t *testing.T) {
	u, _ := url.Parse("https://mcp.example/mcp")
	sink := &gatewayAuditSink{}
	g, err := NewGatewayWithAuthorizer(&http.Client{Timeout: time.Second}, []Target{{Name: "demo", URL: u, Tools: map[string]struct{}{"system.whoami": {}}}}, testAuthorizer{allow: true}, sink)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "system.whoami")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing verified identity status=%d", rr.Code)
	}

	g.authz = testAuthorizer{allow: false}
	req = req.WithContext(identity.WithContext(req.Context(), requestIdentityForGatewayTest(t)))
	rr = httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("policy denial status=%d", rr.Code)
	}
	if sink.event.Type != audit.MCPToolDenied || sink.event.ReasonCode != "policy_denied" {
		t.Fatalf("policy denial was not audited safely: %+v", sink.event)
	}
}

type gatewayAuditSink struct {
	event audit.Event
	err   error
}

func (s *gatewayAuditSink) Write(event audit.Event) error { s.event = event; return s.err }

func TestGatewayAllowedDecisionFailsClosedWhenAuditUnavailable(t *testing.T) {
	u, _ := url.Parse("https://mcp.example/mcp")
	sink := &gatewayAuditSink{err: errors.New("unavailable")}
	g, err := NewGatewayWithAuthorizer(&http.Client{Timeout: time.Second}, []Target{{Name: "demo", URL: u, Tools: map[string]struct{}{"system.whoami": {}}}}, testAuthorizer{allow: true}, sink)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "system.whoami")
	req = req.WithContext(identity.WithContext(req.Context(), requestIdentityForGatewayTest(t)))
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d", rr.Code)
	}
}

func requestIdentityForGatewayTest(t *testing.T) identity.RequestIdentityContext {
	t.Helper()
	user, _ := identity.NewUserIdentity("user")
	agent, _ := identity.NewAgentIdentity("urn:agent:demo", "instance")
	workload, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	caller, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	txn, _ := identity.NewTransactionIdentity("tx", "system.whoami")
	auth, _ := identity.NewAuthorizationContext([]string{"mcp:invoke"})
	value, _ := identity.NewRequestIdentityContext(user, agent, workload, caller, txn, auth)
	return value
}
func TestGatewayRejectsUnapprovedToolAndAmbiguousRoute(t *testing.T) {
	u, _ := url.Parse("https://mcp.example/mcp")
	client := &http.Client{Timeout: time.Second}
	if _, err := NewGateway(client, []Target{{Name: "a", URL: u, Tools: map[string]struct{}{"same": {}}}, {Name: "b", URL: u, Tools: map[string]struct{}{"same": {}}}}); err == nil {
		t.Fatal("ambiguous route accepted")
	}
	g, _ := NewGateway(client, []Target{{Name: "a", URL: u, Tools: map[string]struct{}{"allowed": {}}}})
	req := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "denied")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
}
