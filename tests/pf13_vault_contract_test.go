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
	// Naming the records, rather than counting them, means a policy cannot grow
	// by swapping one path for another and still pass.
	reviewed := []string{
		"administrator", "devops", "bootstrap-system",
		"oauth/token-exchange", "oauth/browser", "oauth/lab-user", "oauth/mcp-gateway",
		"runtime-ca", "admin-ca",
	}
	if strings.Count(policy, `capabilities = ["read"]`) != len(reviewed) {
		t.Fatalf("isolated PingFederate runtime policy must expose exactly %d reviewed records", len(reviewed))
	}
	for _, record := range reviewed {
		if !strings.Contains(policy, `path "kv/data/wai/pingfederate-13-1/`+record+`" { capabilities = ["read"] }`) {
			t.Errorf("isolated policy is missing the reviewed read-only record %q", record)
		}
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
		Audience        string   `json:"audience"`
	}
	if err := json.Unmarshal(roleBytes, &role); err != nil {
		t.Fatal(err)
	}
	if strings.Join(role.ServiceAccounts, ",") != "wai-pingfederate-vault-auth" || strings.Join(role.Namespaces, ",") != "wai-pingfederate" || strings.Join(role.Policies, ",") != "wai-pingfederate-13-1" || role.Audience != "vault" {
		t.Fatal("Vault Kubernetes role must bind the exact namespace, ServiceAccount, policy, and audience")
	}
	if strings.Contains(string(roleBytes), "*") || strings.Contains(strings.ToLower(string(roleBytes)), "token_bound_cidrs") {
		t.Fatal("Vault Kubernetes role must not contain wildcard or alternate broad binding")
	}
}

func TestPingFederate13ChartSyncsExactTerraformSecretsWithoutInjectingThem(t *testing.T) {
	vaultBytes, err := os.ReadFile("../deploy/helm/wai-pingfederate/templates/vault.yaml")
	if err != nil {
		t.Fatal(err)
	}
	vault := string(vaultBytes)
	for _, binding := range []string{
		`"oauth/token-exchange" "wai-pf13-oauth-token-exchange"`,
		`"oauth/browser" "wai-pf13-oauth-browser"`,
		`"oauth/lab-user" "wai-pf13-oauth-lab-user"`,
		`"oauth/mcp-gateway" "wai-pf13-oauth-mcp-gateway"`,
	} {
		if !strings.Contains(vault, binding) {
			t.Fatalf("chart is missing exact Terraform secret binding %q", binding)
		}
	}
	statefulBytes, err := os.ReadFile("../deploy/helm/wai-pingfederate/templates/statefulset.yaml")
	if err != nil {
		t.Fatal(err)
	}
	stateful := string(statefulBytes)
	for _, secret := range []string{"wai-pf13-bootstrap-system", "wai-pf13-oauth-token-exchange", "wai-pf13-oauth-browser", "wai-pf13-oauth-lab-user", "wai-pf13-oauth-mcp-gateway"} {
		if strings.Contains(stateful, secret) {
			t.Fatalf("Terraform-only secret must not be injected into the PingFederate runtime: %q", secret)
		}
	}
}
