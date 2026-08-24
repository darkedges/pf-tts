package tests

import (
	"os"
	"strings"
	"testing"
)

func TestIsolatedPingFederate13ContractFailsClosed(t *testing.T) {
	tasks, err := os.ReadFile("../TASKS.md")
	if err != nil {
		t.Fatal(err)
	}
	adr, err := os.ReadFile("../docs/adr/0011-isolated-kubernetes-pingfederate-13-1.md")
	if err != nil {
		t.Fatal(err)
	}
	contract := strings.Join(strings.Fields(string(tasks)+"\n"+string(adr)), " ")
	for _, required := range []string{
		"wai-pingfederate",
		"digest-pinned official PingFederate image",
		"administrator Service and port 9999 remain cluster-private",
		"workbench.ping.darkedges.com",
		"PingFederate remains the only signer",
		"workload-to-AgentID mapping",
		"must not import or mount state from the shared 12.3 release",
		"Reject a derived runtime build context containing anything outside the Dockerfile and tested plugin JAR allowlist",
		"Reject public admin/API routes",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("isolated PF 13.1 contract missing fail-closed requirement %q", required)
		}
	}

	for _, unsafe := range []string{
		"reuse the 12.3 signing keys",
		"trust Cloudflare identity headers",
		"caller-provided AgentID",
		"public administrator Service",
	} {
		if strings.Contains(strings.ToLower(contract), strings.ToLower(unsafe)) {
			t.Errorf("isolated PF 13.1 contract permits unsafe design %q", unsafe)
		}
	}
}
