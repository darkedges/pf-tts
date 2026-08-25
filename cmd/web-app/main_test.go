package main

import (
	"os"
	"strings"
	"testing"
)

func TestWorkbenchUsesStrictPeersAndNoOIDCAddressRewrite(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{"spiffe://example.org/tts/adapter", "spiffe://example.org/gateway/mcp-strict", "StrictRunner", "TTS_ADAPTER_URL"} {
		if !strings.Contains(s, required) {
			t.Fatalf("strict workbench missing %q", required)
		}
	}
	for _, forbidden := range []string{"host.docker.internal", "DialContext", `NewExactPeerPolicy("spiffe://example.org/gateway/mcp")`} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("workbench contains unsafe legacy backchannel behavior %q", forbidden)
		}
	}
}
