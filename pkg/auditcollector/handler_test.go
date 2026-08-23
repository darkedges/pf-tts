package auditcollector

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
)

func requestWithCaller(t *testing.T, method, target, body, caller string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	uri, err := url.Parse(caller)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, URIs: []*url.URL{uri}}
	request.TLS.PeerCertificates = []*x509.Certificate{certificate}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{certificate}}
	return request
}

func newCollector(t *testing.T) *Handler {
	t.Helper()
	store, err := audit.NewStore(audit.StoreConfig{MaximumRecords: 10, MaximumFieldBytes: 256, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{Store: store, AllowedSubmitters: []string{"spiffe://example.org/gateway/mcp"}, QueryCaller: "spiffe://example.org/agent/web-app", MaximumBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestCollectorDerivesSubmitterAndFiltersQueriesByUser(t *testing.T) {
	handler := newCollector(t)
	event := `{"type":"mcp.tool.allowed","transaction_id":"tx","user_id":"user-a","agent_id":"urn:agent:web-app","transaction_workload_id":"spiffe://example.org/agent/web-app","target":"demo:system.whoami","decision":"allow","reason_code":"policy_allowed"}`
	submit := requestWithCaller(t, http.MethodPost, "https://collector/v1/events", event, "spiffe://example.org/gateway/mcp")
	submit.Header.Set("Content-Type", "application/json")
	submitted := httptest.NewRecorder()
	handler.ServeHTTP(submitted, submit)
	if submitted.Code != http.StatusCreated {
		t.Fatalf("submit failed: %d %s", submitted.Code, submitted.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(submitted.Body.Bytes(), &created)

	list := requestWithCaller(t, http.MethodGet, "https://collector/v1/events", "", "spiffe://example.org/agent/web-app")
	list.Header.Set("X-WAI-User-ID", "user-a")
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"submitting_spiffe_id":"spiffe://example.org/gateway/mcp"`) {
		t.Fatalf("safe list failed: %d %s", listed.Code, listed.Body.String())
	}
	other := requestWithCaller(t, http.MethodGet, "https://collector/v1/events/"+created.ID, "", "spiffe://example.org/agent/web-app")
	other.Header.Set("X-WAI-User-ID", "user-b")
	otherResult := httptest.NewRecorder()
	handler.ServeHTTP(otherResult, other)
	if otherResult.Code != http.StatusNotFound {
		t.Fatalf("cross-user guessed ID status = %d", otherResult.Code)
	}
}

func TestCollectorRejectsSpoofedCallerUnknownOversizedAndCredentialData(t *testing.T) {
	handler := newCollector(t)
	tests := []struct {
		name, caller, body string
		status             int
	}{
		{"spoofed workload", "spiffe://example.org/attacker", `{"type":"mcp.tool.allowed","transaction_id":"tx","user_id":"user"}`, http.StatusForbidden},
		{"unknown identity field", "spiffe://example.org/gateway/mcp", `{"type":"mcp.tool.allowed","transaction_id":"tx","user_id":"user","submitting_spiffe_id":"spiffe://attacker"}`, http.StatusBadRequest},
		{"credential shaped", "spiffe://example.org/gateway/mcp", `{"type":"mcp.tool.allowed","transaction_id":"tx","user_id":"Bearer stolen"}`, http.StatusBadRequest},
		{"unknown event type", "spiffe://example.org/gateway/mcp", `{"type":"custom.unreviewed","transaction_id":"tx","user_id":"user"}`, http.StatusBadRequest},
		{"oversized", "spiffe://example.org/gateway/mcp", `{"type":"mcp.tool.allowed","transaction_id":"tx","user_id":"` + strings.Repeat("x", 1100) + `"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := requestWithCaller(t, http.MethodPost, "https://collector/v1/events", test.body, test.caller)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestCollectorRejectsUnboundedOrMalformedTrustConfiguration(t *testing.T) {
	store, _ := audit.NewStore(audit.StoreConfig{MaximumRecords: 1, MaximumFieldBytes: 256, Retention: time.Minute})
	for _, config := range []Config{
		{Store: store, AllowedSubmitters: []string{"not-a-spiffe-id"}, QueryCaller: "spiffe://example.org/agent/web-app", MaximumBodyBytes: 1024},
		{Store: store, AllowedSubmitters: []string{"spiffe://example.org/gateway/mcp"}, QueryCaller: "not-a-spiffe-id", MaximumBodyBytes: 1024},
		{Store: store, AllowedSubmitters: []string{"spiffe://example.org/gateway/mcp"}, QueryCaller: "spiffe://example.org/agent/web-app", MaximumBodyBytes: (1 << 20) + 1},
	} {
		if _, err := New(config); err == nil {
			t.Fatal("unsafe collector trust or capacity configuration accepted")
		}
	}
}
