package tests

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPingFederate13VaultBootstrapIsExplicitAndFailClosed(t *testing.T) {
	data, err := os.ReadFile("../scripts/import-pingfederate-13-1-bootstrap-to-vault.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"-IncludePrivilegedBootstrap", "if (-not $IncludePrivilegedBootstrap)",
		"options = @{ cas = 0 }", "FixedTimeEquals", "AllowAutoRedirect = $false",
		"VAULT_SKIP_VERIFY", "^https://", "vault print token", "X-Vault-Token",
		"bounded non-symlink regular file", "contains a duplicate key", "contains a malformed entry",
		"contains an empty or oversized value", "$Label is incomplete.",
		"configured Vault mount is not KV v2", "exactly one PEM certificate document",
		"no earlier path was written", "without printing secret values",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("privileged Vault importer missing failure control %q", required)
		}
	}
	for _, path := range []string{
		"administrator", "devops", "bootstrap-system", "oauth/token-exchange",
		"oauth/browser", "oauth/lab-user", "oauth/mcp-gateway", "runtime-ca",
	} {
		if !strings.Contains(script, `"$basePath/`+path+`"`) {
			t.Errorf("privileged Vault importer missing isolated record %q", path)
		}
	}
	for _, forbidden := range []string{"-tls-skip-verify", "VAULT_TOKEN=", "approle", "secret_id", "Write-Output $values", "vault kv put", "wai/pingfederate/ca"} {
		if strings.Contains(strings.ToLower(script), strings.ToLower(forbidden)) {
			t.Errorf("privileged Vault importer contains unsafe mechanism %q", forbidden)
		}
	}
}

func TestPingFederate13VaultPolicyAndRoleAreExact(t *testing.T) {
	policyBytes, err := os.ReadFile("../deploy/vault/wai-pingfederate-13-1-policy.hcl")
	if err != nil {
		t.Fatal(err)
	}
	policy := string(policyBytes)
	if strings.Contains(policy, "*") || strings.Contains(policy, `capabilities = ["create"`) || strings.Contains(policy, `capabilities = ["list"`) {
		t.Fatal("isolated PingFederate runtime policy must be exact and read-only")
	}
	if strings.Count(policy, `capabilities = ["read"]`) != 8 {
		t.Fatal("isolated PingFederate runtime policy must expose exactly eight reviewed records")
	}
	for _, forbidden := range []string{"wai/pingfederate/ca", "wai/workbench", `path "sys/`, `path "auth/`} {
		if strings.Contains(policy, forbidden) {
			t.Fatalf("isolated policy crosses an existing or administrative boundary: %s", forbidden)
		}
	}

	roleBytes, err := os.ReadFile("../deploy/vault/wai-pingfederate-13-1-kubernetes-role.json")
	if err != nil {
		t.Fatal(err)
	}
	var role struct {
		ServiceAccounts []string `json:"bound_service_account_names"`
		Namespaces      []string `json:"bound_service_account_namespaces"`
		Policies        []string `json:"token_policies"`
		Audiences       []string `json:"token_audiences"`
	}
	if err := json.Unmarshal(roleBytes, &role); err != nil {
		t.Fatal(err)
	}
	if strings.Join(role.ServiceAccounts, ",") != "wai-pingfederate-vault-auth" || strings.Join(role.Namespaces, ",") != "wai-pingfederate" || strings.Join(role.Policies, ",") != "wai-pingfederate-13-1" || strings.Join(role.Audiences, ",") != "vault" {
		t.Fatal("Vault Kubernetes role must bind the exact namespace, ServiceAccount, policy, and audience")
	}
	if strings.Contains(string(roleBytes), "*") || strings.Contains(strings.ToLower(string(roleBytes)), "token_bound_cidrs") {
		t.Fatal("Vault Kubernetes role must not contain wildcard or alternate broad binding")
	}
}
