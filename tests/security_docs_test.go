package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatModelCoversRequiredScenarios(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "docs", "threat-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	model := strings.ToLower(string(b))
	for _, threat := range []string{"compromised ai agent", "compromised mcp gateway", "compromised mcp server", "compromised downstream api", "stolen subject token", "stolen jwt-svid", "stolen transaction token", "replay", "spire compromise", "pingfederate compromise", "signing-key compromise", "confused deputy", "ssrf", "malicious tool input"} {
		if !strings.Contains(model, threat) {
			t.Fatalf("threat model missing %q", threat)
		}
	}
}

func TestSecurityADRsExistAndPreserveIdentitySeparation(t *testing.T) {
	for i := 1; i <= 6; i++ {
		matches, err := filepath.Glob(filepath.Join("..", "docs", "adr", "000"+string(rune('0'+i))+"-*.md"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("expected one ADR 000%d", i)
		}
	}
	b, err := os.ReadFile(filepath.Join("..", "docs", "adr", "0005-agentid-separate-from-spiffeid.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Callers cannot become another agent") {
		t.Fatal("AgentID/SPIFFEID ADR lost its failure posture")
	}
}
