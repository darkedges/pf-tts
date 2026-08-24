package tests

import (
	"os"
	"strings"
	"testing"
)

func TestStrictCallChainCommandsAreDistinctExactAndUnwired(t *testing.T) {
	files := map[string][]string{
		"../cmd/strict-mcp-gateway/main.go": {
			`spiffe://example.org/gateway/mcp-strict`, `spiffe://example.org/agent/demo`, `spiffe://example.org/mcp/demo-strict`,
			`NewStrictGatewayWithAuthorizer`, `NewStrictTxnMiddleware`, `NewExactPeerPolicy(agentID)`, `NewExactPeerPolicy(mcpID)`, `Addr: ":8543"`, `STRICT_MCP_SERVER_URL`,
		},
		"../cmd/strict-demo-mcp-server/main.go": {
			`spiffe://example.org/mcp/demo-strict`, `spiffe://example.org/gateway/mcp-strict`, `spiffe://example.org/api/demo-strict`,
			`NewStrictDemoServerHandlerWithAPI`, `NewStrictTxnMiddleware`, `NewExactPeerPolicy(gatewayID)`, `NewExactPeerPolicy(apiID)`, `Addr: ":8544"`, `STRICT_DEMO_API_URL`,
		},
		"../cmd/strict-demo-api/main.go": {
			`spiffe://example.org/api/demo-strict`, `spiffe://example.org/mcp/demo-strict`, `StrictDemoAPIHandler`,
			`NewStrictTxnMiddleware`, `NewExactPeerPolicy(mcpID)`, `Addr: ":8545"`,
		},
	}
	for path, required := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, value := range required {
			if !strings.Contains(text, value) {
				t.Fatalf("%s missing strict control %q", path, value)
			}
		}
		for _, forbidden := range []string{"AuthorizeAny", "AuthorizeMemberOf", `Authorization", "Bearer`} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains permissive or legacy behavior %q", path, forbidden)
			}
		}
	}
	compose, err := os.ReadFile("../deploy/docker/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"strict-mcp-gateway:", "strict-demo-mcp-server:", "strict-demo-api:", `profiles: ["txn-token-call-chain"]`} {
		if !strings.Contains(string(compose), required) {
			t.Fatalf("strict command is missing isolated Compose wiring: %q", required)
		}
	}
}
