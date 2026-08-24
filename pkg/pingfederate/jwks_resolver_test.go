package pingfederate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestJWKSKeyResolverReturnsOneExactKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Error("unexpected JWKS request")
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "signing-key", Use: "sig", Algorithm: "RS256"}}})
	}))
	defer server.Close()
	server.Client().Timeout = time.Second
	resolver, err := NewJWKSKeyResolver(server.URL, server.Client(), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveVerificationKey(context.Background(), "signing-key")
	if err != nil || resolved == nil {
		t.Fatalf("key resolution failed: %v", err)
	}
}

func TestJWKSKeyResolverFailsClosed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "signing-key", Use: "sig", Algorithm: "RS256"})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://evil.example/jwks")
			w.WriteHeader(http.StatusFound)
		},
		"duplicate JSON": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[` + string(public) + `],"keys":[]}`))
		},
		"ambiguous kid": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[` + string(public) + `,` + string(public) + `]}`))
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 1025))) },
		"error body": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("signing-key secret"))
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			server.Client().Timeout = time.Second
			resolver, err := NewJWKSKeyResolver(server.URL, server.Client(), 1024)
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveVerificationKey(context.Background(), "signing-key")
			if !errors.Is(err, ErrJWKSResolution) {
				t.Fatalf("unsafe JWKS accepted: %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("JWKS error leaked response content")
			}
		})
	}
	if _, err := NewJWKSKeyResolver("http://pf.example/jwks", &http.Client{Timeout: time.Second}, 1024); !errors.Is(err, ErrJWKSResolution) {
		t.Fatalf("insecure JWKS URL accepted: %v", err)
	}
}
