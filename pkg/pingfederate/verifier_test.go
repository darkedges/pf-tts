package pingfederate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type privateClaims struct {
	AgentID         string `json:"agent_id"`
	AgentInstanceID string `json:"agent_instance_id"`
	WorkloadID      string `json:"workload_id"`
	TransactionID   string `json:"transaction_id"`
	Purpose         string `json:"transaction_purpose"`
	Scope           string `json:"scope"`
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, kid string, standard jwt.Claims, private privateClaims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(standard).Claims(private).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestJWTVerifierValidationMatrix(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(keySet) }))
	defer server.Close()
	server.Client().Timeout = time.Second
	now := time.Now().UTC().Truncate(time.Second)
	baseStandard := jwt.Claims{Issuer: server.URL, Subject: "user-123", Audience: jwt.Audience{"mcp-gateway"}, ID: "jti-1", IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-time.Second)), Expiry: jwt.NewNumericDate(now.Add(20 * time.Second))}
	basePrivate := privateClaims{AgentID: "urn:agent:demo", AgentInstanceID: "instance", WorkloadID: "spiffe://example.org/agent/demo", TransactionID: "tx-1", Purpose: "customer.read", Scope: "mcp:invoke"}
	verifier, err := NewJWTVerifier(VerifierConfig{Issuer: server.URL, JWKSURL: server.URL, Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: time.Second, HTTPClient: server.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := verifier.Verify(context.Background(), signTestToken(t, key, "known", baseStandard, basePrivate), "mcp-gateway"); err != nil || claims.TransactionID != "tx-1" {
		t.Fatalf("good token failed: %#v %v", claims, err)
	}

	tests := []struct {
		name     string
		key      *rsa.PrivateKey
		kid, aud string
		standard func(jwt.Claims) jwt.Claims
		private  func(privateClaims) privateClaims
	}{
		{"bad signature", wrongKey, "known", "mcp-gateway", nil, nil}, {"unknown kid", key, "unknown", "mcp-gateway", nil, nil},
		{"wrong issuer", key, "known", "mcp-gateway", func(c jwt.Claims) jwt.Claims { c.Issuer = "https://other.example"; return c }, nil},
		{"wrong audience", key, "known", "other", nil, nil}, {"expired", key, "known", "mcp-gateway", func(c jwt.Claims) jwt.Claims { c.Expiry = jwt.NewNumericDate(now.Add(-time.Minute)); return c }, nil},
		{"not yet valid", key, "known", "mcp-gateway", func(c jwt.Claims) jwt.Claims { c.NotBefore = jwt.NewNumericDate(now.Add(time.Minute)); return c }, nil},
		{"missing agent", key, "known", "mcp-gateway", nil, func(c privateClaims) privateClaims { c.AgentID = ""; return c }},
		{"missing workload", key, "known", "mcp-gateway", nil, func(c privateClaims) privateClaims { c.WorkloadID = ""; return c }},
		{"missing transaction", key, "known", "mcp-gateway", nil, func(c privateClaims) privateClaims { c.TransactionID = ""; return c }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			standard := baseStandard
			private := basePrivate
			if tt.standard != nil {
				standard = tt.standard(standard)
			}
			if tt.private != nil {
				private = tt.private(private)
			}
			_, err := verifier.Verify(context.Background(), signTestToken(t, tt.key, tt.kid, standard, private), tt.aud)
			if !errors.Is(err, ErrTokenVerification) {
				t.Fatalf("expected verification error, got %v", err)
			}
		})
	}
}
