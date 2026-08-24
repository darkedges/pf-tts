package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/transaction"
)

func TestCallDemoAPIStrictPropagatesOnlyVerifiedTxnToken(t *testing.T) {
	downstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		values := request.Header.Values(transaction.TxnTokenHeader)
		if len(values) != 1 || values[0] != strictGatewayToken || request.Header.Get("Authorization") != "" {
			t.Errorf("strict API credentials mismatch: %#v", request.Header)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"transaction_id": "txn"})
	}))
	defer downstream.Close()
	downstream.Client().Timeout = time.Second
	endpoint, _ := url.Parse(downstream.URL)
	got, err := callDemoAPIStrict(strictMCPContext(t, strictGatewayToken), downstream.Client(), endpoint, 1024, "txn")
	if err != nil || got != "txn" {
		t.Fatalf("strict API call = %q, %v", got, err)
	}
}

func TestCallDemoAPIStrictRejectsUnsafeResponseAndContext(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
		ctx    bool
	}{
		"downstream denial":       {http.StatusForbidden, `{}`, true},
		"correlation mismatch":    {http.StatusOK, `{"transaction_id":"other"}`, true},
		"unknown response field":  {http.StatusOK, `{"transaction_id":"txn","token":"secret"}`, true},
		"missing trusted context": {http.StatusOK, `{"transaction_id":"txn"}`, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			downstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer downstream.Close()
			downstream.Client().Timeout = time.Second
			endpoint, _ := url.Parse(downstream.URL)
			ctx := strictMCPContext(t, strictGatewayToken)
			if !test.ctx {
				ctx = t.Context()
			}
			if _, err := callDemoAPIStrict(ctx, downstream.Client(), endpoint, 1024, "txn"); err == nil || strings.Contains(err.Error(), strictGatewayToken) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe strict API result accepted or leaked: %v", err)
			}
		})
	}
}

func TestStrictDemoAPIHandlerRequiresVerifiedRouteIdentityAndToken(t *testing.T) {
	handler, err := StrictDemoAPIHandler("demo", "system.whoami")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example/customer", nil).WithContext(strictMCPContext(t, strictGatewayToken))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), strictGatewayToken) || !strings.Contains(recorder.Body.String(), `"transaction_id":"txn"`) {
		t.Fatalf("strict API response mismatch: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	for name, mutate := range map[string]func(*http.Request){
		"missing context": func(r *http.Request) { *r = *r.WithContext(t.Context()) },
		"legacy bearer":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer legacy-secret") },
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://api.example/customer", nil).WithContext(strictMCPContext(t, strictGatewayToken))
			mutate(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code < 400 || strings.Contains(recorder.Body.String(), "legacy-secret") || strings.Contains(recorder.Body.String(), strictGatewayToken) {
				t.Fatalf("strict API failure leaked: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
	if _, err := StrictDemoAPIHandler("", "system.whoami"); err == nil {
		t.Fatal("empty strict API route accepted")
	}
}

func TestStrictDemoServerRejectsUnsafeConfiguration(t *testing.T) {
	httpsURL, _ := url.Parse("https://api.example/customer")
	httpURL, _ := url.Parse("http://api.example/customer")
	client := &http.Client{Timeout: time.Second}
	for name, options := range map[string]struct {
		config DemoServerOptions
		bound  int
	}{
		"missing client":   {DemoServerOptions{APIURL: httpsURL}, 1024},
		"unbounded client": {DemoServerOptions{APIClient: &http.Client{}, APIURL: httpsURL}, 1024},
		"non HTTPS":        {DemoServerOptions{APIClient: client, APIURL: httpURL}, 1024},
		"invalid bound":    {DemoServerOptions{APIClient: client, APIURL: httpsURL}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStrictDemoServerHandlerWithAPI(options.config, options.bound); err == nil {
				t.Fatal("unsafe strict MCP server configuration accepted")
			}
		})
	}
}

func TestStrictMCPToolRequiresExactSignedRoute(t *testing.T) {
	ctx := strictMCPContext(t, strictGatewayToken)
	if !signedToolMatches(ctx, "demo", "system.whoami") {
		t.Fatal("exact signed MCP route rejected")
	}
	for _, route := range [][2]string{{"other", "system.whoami"}, {"demo", "customer.get"}, {"", "system.whoami"}} {
		if signedToolMatches(ctx, route[0], route[1]) {
			t.Fatalf("mismatched signed MCP route accepted: %q/%q", route[0], route[1])
		}
	}
	if signedToolMatches(t.Context(), "demo", "system.whoami") {
		t.Fatal("missing signed route accepted")
	}
}
