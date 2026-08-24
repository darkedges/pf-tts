package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelmAndArgoCDSecurityBoundaries(t *testing.T) {
	chartRoot := "../deploy/helm/wai-strict"
	var chart strings.Builder
	err := filepath.Walk(chartRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			chart.Write(data)
			chart.WriteByte('\n')
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	content := chart.String()
	for _, required := range []string{
		"driver: csi.spiffe.io", "automountServiceAccountToken: false",
		"allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true",
		"secretKeyRef:", "authorization.rego", "readOnly: true",
		`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`,
		"workbench.ping.darkedges.com", "workbenchServiceName",
		"kind: VaultConnection", "kind: VaultAuth", "kind: VaultStaticSecret",
		"method: kubernetes", "skipTLSVerify: false", "hmacSecretData: true",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("Helm chart missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"kind: Secret", "stringData:", "privileged: true", ":latest", "cert-manager.io/", "auth-tls-secret", "ssl-passthrough", "tts.ping.darkedges.com", "mcp.ping.darkedges.com", "method: appRole", "skipTLSVerify: true", "vaultToken"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("Helm chart contains unsafe material %q", forbidden)
		}
	}

	argoFiles := []string{"../deploy/argocd/wai-strict-application.example.yaml", "../deploy/argocd/wai-strict-project.yaml"}
	for _, path := range argoFiles {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), "kind: Secret") || strings.Contains(string(data), "client-secret") {
			t.Fatalf("Argo CD manifest %s embeds secret material", path)
		}
	}
	identities, err := os.ReadFile("../deploy/argocd/spire-identities.yaml")
	if err != nil {
		t.Fatal(err)
	}
	identityConfig := string(identities)
	for _, serviceAccount := range []string{"wai-tts-adapter", "wai-strict-gateway", "wai-strict-mcp", "wai-strict-api"} {
		if !strings.Contains(identityConfig, `.PodSpec.ServiceAccountName "`+serviceAccount+`"`) {
			t.Errorf("SPIRE registration does not bind ServiceAccount %q", serviceAccount)
		}
	}
}

func TestHelmStrictPolicyMatchesReviewedSource(t *testing.T) {
	reviewed, err := os.ReadFile("../config/authorization-strict.rego")
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := os.ReadFile("../deploy/helm/wai-strict/files/authorization-strict.rego")
	if err != nil {
		t.Fatal(err)
	}
	normalizeLines := func(value []byte) string {
		lines := strings.Split(strings.ReplaceAll(string(value), "\r\n", "\n"), "\n")
		for index := range lines {
			lines[index] = strings.TrimSpace(lines[index])
		}
		return strings.Join(lines, "\n")
	}
	if normalizeLines(reviewed) != normalizeLines(packaged) {
		t.Fatal("Helm policy differs from the reviewed strict policy")
	}
}

func TestVaultImporterIsNarrowAndFailClosed(t *testing.T) {
	data, err := os.ReadFile("../scripts/import-env-local-to-vault.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"CryptographicOperations]::FixedTimeEquals", "options = @{ cas = 0 }", "VAULT_SKIP_VERIFY",
		"vault print token", "X-Vault-Token", "HttpClientHandler", "AllowAutoRedirect = $false",
		"$ValidateOnly", "PF_CA_FILE must be a non-symlink PEM file no larger than 64 KiB",
		"VAULT_KV_MOUNT", "sys/internal/ui/mounts", "is not a KV v2 secrets engine; refusing to write",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Vault importer missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"PF_ADMIN_PASSWORD", "PING_IDENTITY_DEVOPS_KEY", "TF_VAR_lab_user_password", "-tls-skip-verify", "Write-Output $clientSecret", `"@$file"`, "WriteAllText", "vault kv put"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("Vault importer includes prohibited credential handling %q", forbidden)
		}
	}
}
