package mcp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
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
