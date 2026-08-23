package authorization

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
)

func TestPingAuthorizeSendsOnlyTypedVerifiedDecisionInput(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/governance-engine" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected PingAuthorize request metadata")
		}
		var input pingAuthorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.Attributes["agent_id"] != "urn:agent:demo" || input.Attributes["workload_id"] != "spiffe://example.org/agent/demo" || input.Attributes["immediate_caller_id"] != "spiffe://example.org/agent/demo" || input.Attributes["scope"] != "mcp:invoke read" || input.Attributes["target"] != "demo" || input.Attributes["tool"] != "system.whoami" {
			t.Fatalf("unexpected trusted decision input: %#v", input.Attributes)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validPingAuthorizeResponse(true, "PERMIT", nil)))
	}))
	defer server.Close()
	policy := newTestPingAuthorize(t, server, 500*time.Millisecond)
	value := requestIdentityForPingAuthorizeTest(t)
	value.Authorization.Scope = []string{"read", "mcp:invoke"}
	if err := policy.Authorize(context.Background(), value, "demo", "system.whoami"); err != nil {
		t.Fatal(err)
	}
}

func TestPingAuthorizeFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"deny", http.StatusOK, "application/json", validPingAuthorizeResponse(false, "DENY", nil)},
		{"contradictory", http.StatusOK, "application/json", validPingAuthorizeResponse(true, "DENY", nil)},
		{"missing authorised", http.StatusOK, "application/json", `{"id":"id","deploymentPackageId":"package","timestamp":"now","decision":"PERMIT","status":{"code":"OKAY","messages":[],"errors":[]}}`},
		{"unknown field", http.StatusOK, "application/json", `{"id":"id","deploymentPackageId":"package","timestamp":"now","decision":"PERMIT","authorised":true,"status":{"code":"OKAY","messages":[],"errors":[]},"unexpected":true}`},
		{"unfulfilled obligation", http.StatusOK, "application/json", validPingAuthorizeResponse(true, "PERMIT", []pingAuthorizeStatement{{Code: "must-handle", Obligatory: true}})},
		{"policy error", http.StatusOK, "application/json", `{"id":"id","deploymentPackageId":"package","timestamp":"now","decision":"PERMIT","authorised":true,"status":{"code":"ERROR","messages":[],"errors":["bad"]}}`},
		{"oversized", http.StatusOK, "application/json", `{"padding":"` + string(make([]byte, pingAuthorizeResponseLimit)) + `"}`},
		{"wrong content type", http.StatusOK, "text/plain", validPingAuthorizeResponse(true, "PERMIT", nil)},
		{"server failure", http.StatusBadGateway, "application/json", `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			if err := newTestPingAuthorize(t, server, time.Second).Authorize(context.Background(), requestIdentityForPingAuthorizeTest(t), "demo", "system.whoami"); err == nil {
				t.Fatal("unsafe PingAuthorize result was accepted")
			}
		})
	}
}

func TestPingAuthorizeRejectsUnsafeConfigurationAndAmbiguousScopes(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	for _, endpoint := range []string{"", "http://authorize/governance-engine", "https://authorize/other", "https://user:pass@authorize/governance-engine", "https://authorize/governance-engine?x=1"} {
		if _, err := NewPingAuthorize(client, endpoint, time.Second); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ambiguous scopes reached PDP") }))
	defer server.Close()
	policy := newTestPingAuthorize(t, server, time.Second)
	for _, scopes := range [][]string{{"mcp:invoke", "mcp:invoke"}, {"mcp:invoke read"}, {" mcp:invoke"}} {
		value := requestIdentityForPingAuthorizeTest(t)
		value.Authorization.Scope = scopes
		if policy.Authorize(context.Background(), value, "demo", "system.whoami") == nil {
			t.Fatal("ambiguous scope encoding accepted")
		}
	}
}

func TestPingAuthorizeHonorsCancellationAndTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validPingAuthorizeResponse(true, "PERMIT", nil)))
	}))
	defer server.Close()
	policy := newTestPingAuthorize(t, server, 10*time.Millisecond)
	if policy.Authorize(context.Background(), requestIdentityForPingAuthorizeTest(t), "demo", "system.whoami") == nil {
		t.Fatal("timed-out decision accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if policy.Authorize(cancelled, requestIdentityForPingAuthorizeTest(t), "demo", "system.whoami") == nil {
		t.Fatal("cancelled decision accepted")
	}
}

func newTestPingAuthorize(t *testing.T, server *httptest.Server, timeout time.Duration) *PingAuthorize {
	t.Helper()
	client := server.Client()
	client.Timeout = time.Second
	policy, err := NewPingAuthorize(client, server.URL+"/governance-engine", timeout)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func requestIdentityForPingAuthorizeTest(t *testing.T) identity.RequestIdentityContext {
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

func validPingAuthorizeResponse(authorised bool, decision string, statements []pingAuthorizeStatement) string {
	value := pingAuthorizeResponse{ID: "id", DeploymentPackageID: "package", Timestamp: "now", Decision: decision, Authorised: &authorised, Statements: statements, Status: pingAuthorizeStatus{Code: "OKAY", Messages: []json.RawMessage{}, Errors: []json.RawMessage{}}}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestPingAuthorizeDoesNotAllowDisabledTLSVerification(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec -- deliberate failure fixture
	if _, err := NewPingAuthorize(client, "https://authorize/governance-engine", time.Second); err == nil {
		t.Fatal("TLS verification bypass accepted")
	}
}
