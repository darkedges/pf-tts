package transaction

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type staticVerificationKeys struct {
	key any
	err error
}

func (s staticVerificationKeys) ResolveVerificationKey(_ context.Context, keyID string) (any, error) {
	if keyID != "test-key" || s.err != nil {
		return nil, errors.New("key unavailable")
	}
	return s.key, nil
}

func txnVerifierFixture(t *testing.T) (*TxnTokenVerifier, *rsa.PrivateKey, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier, err := NewTxnTokenVerifier(TxnTokenVerifierConfig{
		Mode: ProfileTxnTokenV11, Issuer: "https://pf.example/tts", TrustDomain: "example.org",
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: time.Second,
		MaximumLifetime: 30 * time.Second, MaximumTokenBytes: 8192, MaximumPayloadBytes: 4096,
		MaximumIdentifierBytes: 256, MaximumContextBytes: 1024, MaximumScopes: 4,
		AllowedScopes:         map[string]struct{}{"mcp.system.whoami": {}, "customer.read": {}},
		WorkloadAgentBindings: map[string]string{"spiffe://example.org/agent/demo": "urn:agent:demo"},
		Keys:                  staticVerificationKeys{key: &key.PublicKey}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, key, now
}

func validTxnPayload(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://pf.example/tts", "sub": "pairwise-user", "aud": "example.org",
		"iat": now.Unix(), "exp": now.Add(20 * time.Second).Unix(), "txn": "txn-1",
		"scope": "mcp.system.whoami", "req_wl": "spiffe://example.org/agent/demo", "jti": "jti-1",
		"tctx": map[string]any{"wai": map[string]any{
			"version": 1, "agent": map[string]any{"id": "urn:agent:demo", "instance_id": "instance-1", "workload_id": "spiffe://example.org/agent/demo"},
			"target": "demo", "tool": "system.whoami",
		}},
		"rctx": map[string]any{"authn": "pwd"},
	}
}

func signTxnPayload(t *testing.T, key any, algorithm jose.SignatureAlgorithm, kid, typ string, payload any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if kid != "" {
		options.WithHeader(jose.HeaderKey("kid"), kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	body, ok := payload.([]byte)
	if !ok {
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	object, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestTxnTokenVerifierAcceptsStrictProfile(t *testing.T) {
	verifier, key, now := txnVerifierFixture(t)
	payload := validTxnPayload(now)
	payload["future_extension"] = map[string]any{"ignored": true}
	claims, err := verifier.Verify(context.Background(), signTxnPayload(t, key, jose.RS256, "test-key", TxnTokenJOSEType, payload))
	if err != nil {
		t.Fatal(err)
	}
	if claims.TransactionID != "txn-1" || claims.Subject != "pairwise-user" || claims.RequestingWorkloadID != "spiffe://example.org/agent/demo" || claims.TransactionContext.WAI.Agent.ID != "urn:agent:demo" || claims.RequestContext == nil || claims.RequestContext.AuthenticationMethod != "pwd" {
		t.Fatalf("unexpected typed claims: %+v", claims)
	}
}

func TestTxnTokenVerifierRejectsHeaderAndSignatureFailures(t *testing.T) {
	verifier, key, now := txnVerifierFixture(t)
	valid := validTxnPayload(now)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"wrong typ":        signTxnPayload(t, key, jose.RS256, "test-key", "at+jwt", valid),
		"missing kid":      signTxnPayload(t, key, jose.RS256, "", TxnTokenJOSEType, valid),
		"unknown kid":      signTxnPayload(t, key, jose.RS256, "other-key", TxnTokenJOSEType, valid),
		"bad signature":    signTxnPayload(t, otherKey, jose.RS256, "test-key", TxnTokenJOSEType, valid),
		"unprotected form": `{"payload":"e30","header":{"typ":"txntoken+jwt"},"signature":"AA"}`,
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrTxnTokenVerification) {
				t.Fatalf("expected verification failure, got %v", err)
			}
		})
	}
	hmacToken := signTxnPayload(t, []byte(strings.Repeat("x", 32)), jose.HS256, "test-key", TxnTokenJOSEType, valid)
	if _, err := verifier.Verify(context.Background(), hmacToken); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("disallowed header algorithm accepted: %v", err)
	}
	duplicateHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"HS256","kid":"test-key","typ":"txntoken+jwt"}`)) + ".e30.AA"
	if _, err := verifier.Verify(context.Background(), duplicateHeader); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("duplicate protected header accepted: %v", err)
	}
}

func TestTxnTokenVerifierRejectsClaimAndBindingFailures(t *testing.T) {
	verifier, key, now := txnVerifierFixture(t)
	tests := map[string]func(map[string]any){
		"missing subject":     func(p map[string]any) { delete(p, "sub") },
		"missing transaction": func(p map[string]any) { delete(p, "txn") },
		"wrong audience type": func(p map[string]any) { p["aud"] = []string{"example.org"} },
		"wrong issuer":        func(p map[string]any) { p["iss"] = "https://evil.example" },
		"wrong audience":      func(p map[string]any) { p["aud"] = "other.org" },
		"expired": func(p map[string]any) {
			p["iat"] = now.Add(-40 * time.Second).Unix()
			p["exp"] = now.Add(-2 * time.Second).Unix()
		},
		"future issued":     func(p map[string]any) { p["iat"] = now.Add(2 * time.Second).Unix() },
		"excess lifetime":   func(p map[string]any) { p["exp"] = now.Add(31 * time.Second).Unix() },
		"scope expansion":   func(p map[string]any) { p["scope"] = "admin.all" },
		"duplicate scope":   func(p map[string]any) { p["scope"] = "customer.read customer.read" },
		"workload conflict": func(p map[string]any) { p["req_wl"] = "spiffe://example.org/agent/other" },
		"agent conflict": func(p map[string]any) {
			p["tctx"].(map[string]any)["wai"].(map[string]any)["agent"].(map[string]any)["id"] = "urn:agent:forged"
		},
		"unknown wai field":  func(p map[string]any) { p["tctx"].(map[string]any)["wai"].(map[string]any)["caller"] = "forged" },
		"unknown rctx field": func(p map[string]any) { p["rctx"].(map[string]any)["ip"] = "127.0.0.1" },
		"oversized context": func(p map[string]any) {
			p["tctx"].(map[string]any)["wai"].(map[string]any)["target"] = strings.Repeat("x", 1025)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := validTxnPayload(now)
			mutate(payload)
			token := signTxnPayload(t, key, jose.RS256, "test-key", TxnTokenJOSEType, payload)
			if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrTxnTokenVerification) {
				t.Fatalf("expected verification failure, got %v", err)
			}
		})
	}
}

func TestTxnTokenVerifierRejectsDuplicateJSONAndOversizedToken(t *testing.T) {
	verifier, key, now := txnVerifierFixture(t)
	raw := []byte(`{"iss":"https://pf.example/tts","iss":"https://evil.example","sub":"user","aud":"example.org","iat":` +
		strconv.FormatInt(now.Unix(), 10) + `,"exp":` + strconv.FormatInt(now.Add(20*time.Second).Unix(), 10) +
		`,"txn":"txn","scope":"mcp.system.whoami","req_wl":"spiffe://example.org/agent/demo","tctx":{"wai":{"version":1,"agent":{"id":"urn:agent:demo","instance_id":"i","workload_id":"spiffe://example.org/agent/demo"},"target":"demo","tool":"system.whoami"}}}`)
	if _, err := verifier.Verify(context.Background(), signTxnPayload(t, key, jose.RS256, "test-key", TxnTokenJOSEType, raw)); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("duplicate claim accepted: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), strings.Repeat("x", 8193)); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("oversized token accepted: %v", err)
	}
}

func TestTxnTokenVerifierConfigurationFailsClosed(t *testing.T) {
	_, key, _ := txnVerifierFixture(t)
	base := TxnTokenVerifierConfig{
		Mode: ProfileLegacyWAIJWT, Issuer: "https://pf.example/tts", TrustDomain: "example.org",
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, MaximumLifetime: 30 * time.Second,
		MaximumTokenBytes: 8192, MaximumPayloadBytes: 4096, MaximumIdentifierBytes: 256,
		MaximumContextBytes: 1024, MaximumScopes: 4, AllowedScopes: map[string]struct{}{"customer.read": {}},
		WorkloadAgentBindings: map[string]string{"spiffe://example.org/agent/demo": "urn:agent:demo"},
		Keys:                  staticVerificationKeys{key: &key.PublicKey},
	}
	if _, err := NewTxnTokenVerifier(base); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("legacy mode must not instantiate strict verifier: %v", err)
	}
	base.Mode = "auto"
	if _, err := NewTxnTokenVerifier(base); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("auto mode must fail closed: %v", err)
	}
}

func TestTxnTokenVerifierCopiesTrustedPolicyConfiguration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	scopes := map[string]struct{}{"customer.read": {}}
	bindings := map[string]string{"spiffe://example.org/agent/demo": "urn:agent:demo"}
	verifier, err := NewTxnTokenVerifier(TxnTokenVerifierConfig{
		Mode: ProfileTxnTokenV11, Issuer: "https://pf.example/tts", TrustDomain: "example.org",
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, MaximumLifetime: 30 * time.Second,
		MaximumTokenBytes: 8192, MaximumPayloadBytes: 4096, MaximumIdentifierBytes: 256,
		MaximumContextBytes: 1024, MaximumScopes: 4, AllowedScopes: scopes,
		WorkloadAgentBindings: bindings, Keys: staticVerificationKeys{key: &key.PublicKey},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	scopes["admin.all"] = struct{}{}
	bindings["spiffe://example.org/agent/demo"] = "urn:agent:forged"
	payload := validTxnPayload(now)
	payload["scope"] = "admin.all"
	payload["tctx"].(map[string]any)["wai"].(map[string]any)["agent"].(map[string]any)["id"] = "urn:agent:forged"
	if _, err := verifier.Verify(context.Background(), signTxnPayload(t, key, jose.RS256, "test-key", TxnTokenJOSEType, payload)); !errors.Is(err, ErrTxnTokenVerification) {
		t.Fatalf("post-construction policy mutation changed verifier trust: %v", err)
	}
}
