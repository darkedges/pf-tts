package pingfederate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExchangeSendsExactFormAndCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			t.Errorf("unexpected method/query")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"grant_type": TokenExchangeGrantType, "subject_token": "subject-secret", "subject_token_type": AccessTokenType, "actor_token": "actor-secret", "actor_token_type": JWTTokenType, "requested_token_type": AccessTokenType, "audience": "mcp-gateway", "scope": "mcp:invoke system:whoami"}
		for key, value := range want {
			if r.Form.Get(key) != value {
				t.Errorf("%s=%q want %q", key, r.Form.Get(key), value)
			}
		}
		if len(r.Form) != len(want) {
			t.Errorf("unexpected form fields: %v", r.Form)
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "client-secret" {
			t.Error("invalid client authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"transaction-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":20,"scope":"mcp:invoke"}`))
	}))
	defer server.Close()
	server.Client().Timeout = time.Second
	client, err := NewClient(server.URL, "client", "client-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "subject-secret", ActorToken: "actor-secret", SubjectTokenType: AccessTokenType, ActorTokenType: JWTTokenType, Audience: "mcp-gateway", Scope: []string{"mcp:invoke", "system:whoami"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "transaction-secret" || result.ExpiresIn != 20 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestExchangeErrorsRedactCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_actor_token","error_description":"actor-secret"}`))
	}))
	defer server.Close()
	server.Client().Timeout = time.Second
	client, err := NewClient(server.URL, "client", "client-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "subject-secret", ActorToken: "actor-secret", SubjectTokenType: AccessTokenType, ActorTokenType: JWTTokenType, Audience: "mcp-gateway"})
	if !errors.Is(err, ErrExchangeFailed) {
		t.Fatalf("expected exchange failure, got %v", err)
	}
	for _, secret := range []string{"subject-secret", "actor-secret", "client-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %s", secret)
		}
	}
}

func TestNewClientRequiresHTTPSAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		client   *http.Client
	}{{"http://pf.example/token", &http.Client{Timeout: time.Second}}, {"https://pf.example/token?token=secret", &http.Client{Timeout: time.Second}}, {"https://pf.example/token", &http.Client{}}} {
		if _, err := NewClient(tc.endpoint, "client", "secret", tc.client); !errors.Is(err, ErrInvalidExchange) {
			t.Fatalf("expected invalid client config, got %v", err)
		}
	}
}

func TestExchangeRejectsRedirectDuplicateAndRefreshResponses(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://evil.example/token")
			w.WriteHeader(http.StatusFound)
		},
		"duplicate": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"first","access_token":"second","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":20}`))
		},
		"refresh": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"transaction-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":20,"refresh_token":"prohibited"}`))
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			server.Client().Timeout = time.Second
			client, err := NewClient(server.URL, "client", "client-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "subject-secret", ActorToken: "actor-secret", SubjectTokenType: AccessTokenType, ActorTokenType: JWTTokenType, Audience: "example.org", Scope: []string{"mcp.system.whoami"}})
			if !errors.Is(err, ErrExchangeFailed) {
				t.Fatalf("unsafe response accepted: %v", err)
			}
			for _, secret := range []string{"subject-secret", "actor-secret", "client-secret", "transaction-secret", "prohibited"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked %q", secret)
				}
			}
		})
	}
}
