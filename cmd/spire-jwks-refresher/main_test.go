package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerificationKeysTranslatesOnlyReviewedJWTAuthorities(t *testing.T) {
	published := jwks{Keys: []jsonWebKey{
		// An X.509 authority: no key ID, and irrelevant to token verification.
		{Use: "x509-svid", Kty: "RSA", N: "x509-modulus", E: "AQAB"},
		{Use: "jwt-svid", Kty: "RSA", Kid: "rsa-key", N: "modulus", E: "AQAB"},
		{Use: "jwt-svid", Kty: "EC", Kid: "ec-key", Crv: "P-256", X: "x-coordinate", Y: "y-coordinate"},
	}}
	result, err := verificationKeys(published)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Keys) != 2 {
		t.Fatalf("expected only the JWT authorities, got %d keys", len(result.Keys))
	}
	for _, key := range result.Keys {
		// SPIRE marks JWT authorities "jwt-svid", which a verification key
		// selector will not consider, and leaves the algorithm unpinned.
		if key.Use != "sig" {
			t.Errorf("key %s was not translated to a verification use: %q", key.Kid, key.Use)
		}
		if key.Alg == "" {
			t.Errorf("key %s has no pinned algorithm", key.Kid)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	// Only public material may be written into configuration.
	for _, forbidden := range []string{"\"d\"", "\"p\"", "\"q\"", "x509-modulus"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("translated key set carries %s", forbidden)
		}
	}
}

func TestVerificationKeysRejectsAmbiguousOrUnreviewedAuthorities(t *testing.T) {
	for name, published := range map[string]jwks{
		"no key ID": {Keys: []jsonWebKey{
			{Use: "jwt-svid", Kty: "RSA", N: "modulus", E: "AQAB"},
		}},
		"duplicate key ID": {Keys: []jsonWebKey{
			{Use: "jwt-svid", Kty: "RSA", Kid: "same", N: "modulus", E: "AQAB"},
			{Use: "jwt-svid", Kty: "RSA", Kid: "same", N: "other", E: "AQAB"},
		}},
		"unreviewed key type": {Keys: []jsonWebKey{
			{Use: "jwt-svid", Kty: "OKP", Kid: "ed25519-key"},
		}},
		"unreviewed curve": {Keys: []jsonWebKey{
			{Use: "jwt-svid", Kty: "EC", Kid: "p521-key", Crv: "P-521", X: "x", Y: "y"},
		}},
		"missing public material": {Keys: []jsonWebKey{
			{Use: "jwt-svid", Kty: "RSA", Kid: "rsa-key", E: "AQAB"},
		}},
		"no JWT authority at all": {Keys: []jsonWebKey{
			{Use: "x509-svid", Kty: "RSA", N: "modulus", E: "AQAB"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verificationKeys(published); err == nil {
				t.Fatal("an ambiguous or unreviewed authority was accepted")
			}
		})
	}
}

// The refresher rewrites live trust configuration, so it must rewrite only when
// the trusted set actually changed. Comparing by key identifier is what makes a
// no-op run a no-op.
func TestSameKeySetComparesIdentifiersRegardlessOfOrder(t *testing.T) {
	current := jwks{Keys: []jsonWebKey{{Kid: "b"}, {Kid: "a"}}}
	if !sameKeySet(current, jwks{Keys: []jsonWebKey{{Kid: "a"}, {Kid: "b"}}}) {
		t.Fatal("the same key identifiers in a different order were treated as a change")
	}
	if sameKeySet(current, jwks{Keys: []jsonWebKey{{Kid: "a"}, {Kid: "b"}, {Kid: "c"}}}) {
		t.Fatal("a newly prepared authority was treated as no change")
	}
	if sameKeySet(current, jwks{Keys: []jsonWebKey{{Kid: "a"}}}) {
		t.Fatal("a retired authority was treated as no change")
	}
}

func TestConfiguredJWKSFailsClosedOnAnUnexpectedShape(t *testing.T) {
	for name, processor := range map[string]map[string]any{
		"no configuration": {},
		"no fields":        {"configuration": map[string]any{}},
		"no JWKS field": {"configuration": map[string]any{
			"fields": []any{map[string]any{"name": "Trust Domain", "value": "example.org"}},
		}},
		"malformed JWKS": {"configuration": map[string]any{
			"fields": []any{map[string]any{"name": jwksField, "value": "not json"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := configuredJWKS(processor); err == nil {
				t.Fatal("an unexpected processor shape was accepted")
			}
		})
	}
}
