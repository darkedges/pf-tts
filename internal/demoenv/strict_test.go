package demoenv

import "testing"

func TestStrictTxnVerifierRejectsMissingOrUnsafeConfiguration(t *testing.T) {
	tests := map[string]struct{ issuer, jwks string }{
		"missing issuer": {"", "https://pf.example/pf/JWKS"},
		"missing JWKS":   {"https://pf.example", ""},
		"non HTTPS JWKS": {"https://pf.example", "http://pf.example/pf/JWKS"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PF_TRANSACTION_ISSUER", test.issuer)
			t.Setenv("PF_JWKS_URL", test.jwks)
			t.Setenv("PF_CA_FILE", "")
			if _, err := StrictTxnVerifier(); err == nil {
				t.Fatal("unsafe strict verifier configuration accepted")
			}
		})
	}
}
