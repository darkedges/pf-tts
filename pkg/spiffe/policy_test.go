package spiffe

import "testing"

func TestExactPeerPolicy(t *testing.T) {
	p, err := NewExactPeerPolicy("spiffe://example.org/gateway/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !p.AuthorizeSPIFFEID("spiffe://example.org/gateway/mcp") || p.AuthorizeSPIFFEID("spiffe://example.org/agent/demo") {
		t.Fatal("exact policy authorized wrong identity")
	}
	if _, err := NewExactPeerPolicy(); err == nil {
		t.Fatal("empty policy must fail")
	}
}
