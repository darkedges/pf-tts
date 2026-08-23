package main

import (
	"context"
	"testing"
)

func TestConfiguredAuthorizerDoesNotFallbackOnUnsafeConfiguration(t *testing.T) {
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
}
