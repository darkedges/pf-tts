package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/workload-agent-identity/internal/demoenv"
)

func TestStrictCallChainCommandsAreDistinctExactAndUnwired(t *testing.T) {
	files := map[string][]string{
		"../cmd/strict-mcp-gateway/main.go": {
			`spiffe://example.org/gateway/mcp-strict`, `spiffe://example.org/agent/demo`, `spiffe://example.org/mcp/demo-strict`,
			`NewStrictGatewayWithAuthorizer`, `NewStrictTxnMiddleware`, `NewExactPeerPolicy(agentID, webAgentID)`, `NewExactPeerPolicy(mcpID)`, `Addr: ":8543"`, `STRICT_MCP_SERVER_URL`,
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

// Every strict hop must verify the transaction token against the same reviewed
// workload-to-AgentID bindings. When the gateway accepted the workbench binding
// but the MCP server and API still accepted only the demo agent, a fully valid
// workbench transaction was verified at the gateway and then silently rejected
// one hop later, with no audit event to explain it.
func TestStrictHopsShareOneReviewedWorkloadAgentBindingSet(t *testing.T) {
	for _, command := range []string{"strict-mcp-gateway", "strict-demo-mcp-server", "strict-demo-api"} {
		body, err := os.ReadFile(filepath.Join("..", "cmd", command, "main.go"))
		if err != nil {
			t.Fatal(err)
		}
		source := string(body)
		if !strings.Contains(source, "demoenv.StrictTxnVerifierForBindings(demoenv.StrictWorkloadAgentBindings())") &&
			!strings.Contains(source, "demoenv.StrictTxnVerifier()") {
			t.Errorf("%s must verify against the shared reviewed bindings, not its own map", command)
		}
		if strings.Contains(source, `StrictTxnVerifierForBindings(map[string]string{`) {
			t.Errorf("%s declares an inline binding map that can drift from the other strict hops", command)
		}
	}
	bindings := demoenv.StrictWorkloadAgentBindings()
	expected := map[string]string{
		"spiffe://example.org/agent/demo":    "urn:agent:demo",
		"spiffe://example.org/agent/web-app": "urn:agent:web-app",
	}
	if len(bindings) != len(expected) {
		t.Fatalf("reviewed strict bindings changed size: got %d, want %d", len(bindings), len(expected))
	}
	for workload, agent := range expected {
		if bindings[workload] != agent {
			t.Errorf("reviewed strict binding for %q is %q, want %q", workload, bindings[workload], agent)
		}
	}
	for workload, agent := range bindings {
		if workload == "" || agent == "" || strings.Contains(workload, "*") || strings.Contains(agent, "*") {
			t.Errorf("reviewed strict binding %q=%q is empty or a wildcard", workload, agent)
		}
	}
}
