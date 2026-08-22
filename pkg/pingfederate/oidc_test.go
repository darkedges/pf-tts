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

type testOIDCClaims struct {
	Nonce string `json:"nonce"`
	AZP   string `json:"azp,omitempty"`
}

func signOIDCToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims, nonce, azp string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Claims(testOIDCClaims{Nonce: nonce, AZP: azp}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyIDTokenRejectsUntrustedIdentity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(keySet) }))
	defer server.Close()
	server.Client().Timeout = time.Second
	now := time.Now().UTC().Truncate(time.Second)
	verifier, err := NewJWTVerifier(VerifierConfig{Issuer: server.URL, JWKSURL: server.URL, Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: time.Second, HTTPClient: server.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	base := jwt.Claims{Issuer: server.URL, Subject: "user-123", Audience: jwt.Audience{"web-client"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}
	if subject, err := verifier.VerifyIDToken(context.Background(), signOIDCToken(t, key, "known", base, "nonce", ""), "web-client", "nonce"); err != nil || subject != "user-123" {
		t.Fatalf("valid token failed: %q %v", subject, err)
	}

	tests := []struct {
		name, nonce, expectedNonce string
		key                        *rsa.PrivateKey
		claims                     func(jwt.Claims) jwt.Claims
	}{
		{name: "wrong nonce", key: key, nonce: "attacker", expectedNonce: "nonce"},
		{name: "wrong issuer", key: key, nonce: "nonce", expectedNonce: "nonce", claims: func(c jwt.Claims) jwt.Claims { c.Issuer = "https://attacker.example"; return c }},
		{name: "wrong audience", key: key, nonce: "nonce", expectedNonce: "nonce", claims: func(c jwt.Claims) jwt.Claims { c.Audience = jwt.Audience{"other-client"}; return c }},
		{name: "bad signature", key: wrongKey, nonce: "nonce", expectedNonce: "nonce"},
		{name: "expired", key: key, nonce: "nonce", expectedNonce: "nonce", claims: func(c jwt.Claims) jwt.Claims { c.Expiry = jwt.NewNumericDate(now.Add(-time.Minute)); return c }},
		{name: "missing issued at", key: key, nonce: "nonce", expectedNonce: "nonce", claims: func(c jwt.Claims) jwt.Claims { c.IssuedAt = nil; return c }},
		{name: "future issued at", key: key, nonce: "nonce", expectedNonce: "nonce", claims: func(c jwt.Claims) jwt.Claims { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)); return c }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := base
			if tt.claims != nil {
				claims = tt.claims(claims)
			}
			_, err := verifier.VerifyIDToken(context.Background(), signOIDCToken(t, tt.key, "known", claims, tt.nonce, ""), "web-client", tt.expectedNonce)
			if !errors.Is(err, ErrTokenVerification) {
				t.Fatalf("expected verification failure, got %v", err)
			}
		})
	}
}

func TestVerifyIDTokenRejectsAmbiguousAudienceWithoutAuthorizedParty(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "known"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(keySet) }))
	defer server.Close()
	server.Client().Timeout = time.Second
	now := time.Now()
	verifier, _ := NewJWTVerifier(VerifierConfig{Issuer: server.URL, JWKSURL: server.URL, Algorithms: []jose.SignatureAlgorithm{jose.RS256}, HTTPClient: server.Client(), Now: func() time.Time { return now }})
	claims := jwt.Claims{Issuer: server.URL, Subject: "user", Audience: jwt.Audience{"web-client", "other"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}
	_, err := verifier.VerifyIDToken(context.Background(), signOIDCToken(t, key, "known", claims, "nonce", "attacker"), "web-client", "nonce")
	if !errors.Is(err, ErrTokenVerification) {
		t.Fatalf("expected ambiguous audience rejection, got %v", err)
	}
}
