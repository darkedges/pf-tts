package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestCallDemoAPIRejectsTransactionCorrelationMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer immutable-token" {
			t.Error("immutable token was not forwarded exactly")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"transaction_id":"different-transaction"}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = time.Second
	if _, err := callDemoAPI(context.Background(), client, endpoint, "immutable-token", "expected-transaction"); err == nil {
		t.Fatal("downstream transaction correlation mismatch accepted")
	}
}

func TestDemoServerWithAPIRejectsUntrustedEndpoint(t *testing.T) {
	endpoint, _ := url.Parse("http://demo-api:8445")
	if _, err := NewDemoServerHandlerWithAPI(DemoServerOptions{APIClient: &http.Client{Timeout: time.Second}, APIURL: endpoint}); err == nil {
		t.Fatal("non-HTTPS downstream API endpoint accepted")
	}
}
