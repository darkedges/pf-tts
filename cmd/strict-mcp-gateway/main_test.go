package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredAuthorizerDoesNotFallbackOnUnsafeConfiguration(t *testing.T) {
	// An unrecognised provider must refuse to start. Falling back to the default
	// would silently enforce a different policy than the operator asked for.
	t.Setenv("AUTHORIZATION_PROVIDER", "unknown")
	if _, err := configuredAuthorizer(context.Background()); err == nil {
		t.Fatal("unknown authorization provider fell back to another policy")
	}

	t.Setenv("AUTHORIZATION_PROVIDER", "pingauthorize")
	t.Setenv("PINGAUTHORIZE_URL", "https://pingauthorize:1443/governance-engine")
	t.Setenv("PINGAUTHORIZE_CA_FILE", "")
	if _, err := configuredAuthorizer(context.Background()); err == nil {
		t.Fatal("PingAuthorize started without an explicit trust anchor")
	}

	// The decision point must be addressed over TLS at its exact governance
	// endpoint; the adapter has no ServerName override to fall back on.
	anchor := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(anchor, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PINGAUTHORIZE_CA_FILE", anchor)
	if _, err := configuredAuthorizer(context.Background()); err == nil {
		t.Fatal("PingAuthorize started with an unusable trust anchor")
	}

	for name, endpoint := range map[string]string{
		"plaintext":     "http://pingauthorize:1443/governance-engine",
		"wrong path":    "https://pingauthorize:1443/other",
		"with userinfo": "https://user:pass@pingauthorize:1443/governance-engine",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PINGAUTHORIZE_URL", endpoint)
			if _, err := configuredAuthorizer(context.Background()); err == nil {
				t.Fatalf("PingAuthorize accepted an unsafe endpoint: %s", endpoint)
			}
		})
	}
}

// The strict chain runs OPA unless told otherwise, so an unset provider must
// route to the same branch as an explicit "opa". Both read the mounted rego, so
// in a unit test both fail identically on the absent file; an unset value that
// had started routing elsewhere would report a different error.
func TestConfiguredAuthorizerDefaultsToTheReviewedRegoPolicy(t *testing.T) {
	t.Setenv("PINGAUTHORIZE_URL", "")
	t.Setenv("PINGAUTHORIZE_CA_FILE", "")

	t.Setenv("AUTHORIZATION_PROVIDER", "")
	_, unset := configuredAuthorizer(context.Background())
	t.Setenv("AUTHORIZATION_PROVIDER", "opa")
	_, explicit := configuredAuthorizer(context.Background())
	t.Setenv("AUTHORIZATION_PROVIDER", "OPA")
	_, uppercase := configuredAuthorizer(context.Background())

	if unset == nil || explicit == nil {
		t.Skip("a rego policy is mounted in this environment; the branch cannot be told apart by error")
	}
	if unset.Error() != explicit.Error() || uppercase.Error() != explicit.Error() {
		t.Fatalf("an unset or differently cased provider did not route to the reviewed rego policy: unset=%v explicit=%v uppercase=%v", unset, explicit, uppercase)
	}
}
