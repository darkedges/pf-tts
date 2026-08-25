package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type publicationLock struct {
	SourceRevision    string            `json:"sourceRevision"`
	RequiredPlatforms []string          `json:"requiredPlatforms"`
	Images            map[string]string `json:"images"`
}

var immutableImage = regexp.MustCompile(`^[^:@[:space:]]+(?:/[^:@[:space:]]+)+@sha256:[a-f0-9]{64}$`)

func validatePublicationLock(lock publicationLock, helmValues string) error {
	if lock.SourceRevision == "" {
		return fmt.Errorf("source revision is required")
	}
	platforms := strings.Join(lock.RequiredPlatforms, ",")
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		if !strings.Contains(platforms, platform) {
			return fmt.Errorf("required platform %s is missing", platform)
		}
	}
	for _, name := range []string{"ttsAdapter", "gateway", "mcpServer", "api", "workbench", "auditCollector"} {
		image, ok := lock.Images[name]
		if !ok {
			return fmt.Errorf("required image %s is missing", name)
		}
		if !immutableImage.MatchString(image) {
			return fmt.Errorf("image %s is not digest pinned", name)
		}
		parts := strings.Split(image, "@")
		if !strings.Contains(helmValues, "repository: "+parts[0]) || !strings.Contains(helmValues, `digest: "`+parts[1]+`"`) {
			return fmt.Errorf("image %s does not match reviewed Helm values", name)
		}
	}
	return nil
}

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
		"workbench.ping.darkedges.com", "workbenchServiceName", "tst.ping.darkedges.com", "pingFederateHost",
		"kind: VaultConnection", "kind: VaultAuth", "kind: VaultStaticSecret",
		"method: kubernetes", "skipTLSVerify: false", "hmacSecretData: true",
		"wai-strict-workbench", "wai-strict-audit", "TTS_ADAPTER_URL", "AUDIT_COLLECTOR_URL",
		"spiffe://example.org/agent/web-app", "spiffe://example.org/audit/collector",
		"kubernetes.io/metadata.name: ingress-nginx", "app.kubernetes.io/component: controller", "port: 8446",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("Helm chart missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"kind: Secret", "stringData:", "privileged: true", ":latest", "cert-manager.io/", "auth-tls-secret", "ssl-passthrough", "tts.ping.darkedges.com", "mcp.ping.darkedges.com", "method: appRole", "skipTLSVerify: true", "vaultToken", "host.docker.internal", "spiffe://example.org/gateway/mcp\""} {
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
	if strings.Count(identityConfig, "className: spire-system-spire") != 6 {
		t.Fatal("each strict SPIFFE registration must bind the installed controller class")
	}
	for _, serviceAccount := range []string{"wai-tts-adapter", "wai-strict-gateway", "wai-strict-mcp", "wai-strict-api", "wai-strict-workbench", "wai-strict-audit"} {
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

func TestSingleHostnameIngressIsEngineAllowlisted(t *testing.T) {
	template, err := os.ReadFile("../deploy/helm/wai-strict/templates/ingress.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(template)
	for _, required := range []string{
		`list "/as/" "/pf/" "/idp/"`,
		".Values.ingress.pingFederateEngineExternalName",
		"targetPort: {{ .Values.ingress.pingFederateEngineServicePort }}",
		`nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-name: "localhost"`,
		".Values.ingress.host",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("public ingress missing control %q", required)
		}
	}
	for _, forbidden := range []string{"wai-pingfederate-admin", "port: 9999", `"/pf-admin`, `"/pingfederate`} {
		if strings.Contains(content, forbidden) {
			t.Errorf("public ingress exposes forbidden PingFederate surface %q", forbidden)
		}
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
		"CreateFromPem($workbenchCertificatePEM, $workbenchPrivateKeyPEM)", "MatchesHostname('localhost'", "'ca.crt'",
		"PingFederateCAFile",
		"'client-id' = 'wai-web-app'",
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

func TestStrictVaultPolicyAndRoleAreExactReadOnly(t *testing.T) {
	policyBytes, err := os.ReadFile("../deploy/vault/wai-strict-policy.hcl")
	if err != nil {
		t.Fatal(err)
	}
	policy := string(policyBytes)
	for _, path := range []string{
		"kv/data/wai/pingfederate-13-1/runtime-ca",
		"kv/data/wai/pingfederate-13-1/oauth/token-exchange",
		"kv/data/wai/workbench",
	} {
		if !strings.Contains(policy, path) {
			t.Errorf("strict Vault policy is missing %q", path)
		}
	}
	for _, forbidden := range []string{"*", "create", "update", "delete", "sudo", `path "kv/data/wai/*`} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("strict Vault policy contains over-broad capability %q", forbidden)
		}
	}

	roleBytes, err := os.ReadFile("../scripts/configure-wai-strict-vault-role.ps1")
	if err != nil {
		t.Fatal(err)
	}
	role := string(roleBytes)
	for _, required := range []string{"bound_service_account_names=wai-vault-auth", "bound_service_account_namespaces=wai-strict", "audience=vault", "token_policies=wai-strict", "token_max_ttl=30m"} {
		if !strings.Contains(role, required) {
			t.Errorf("strict Vault role is missing %q", required)
		}
	}
}

func TestContainerPublicationExcludesLocalSecrets(t *testing.T) {
	dockerignore, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	content := string(dockerignore)
	for _, required := range []string{
		".env.*", "deploy/pingfederate/generated", "deploy/pingfederate/discovered",
		"deploy/pingfederate/terraform/*.tfvars", "deploy/pingauthorize/generated",
		"deploy/spire/generated", "deploy/web/generated", "**/*.pem", "**/*.key",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("Docker build context does not exclude sensitive path %q", required)
		}
	}

	makefile, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	makeContent := string(makefile)
	for _, required := range []string{
		"REGISTRY_HOST ?= docker.io", "IMAGE_PREFIX ?= pf-tts-", "docker login '$(REGISTRY_HOST)'", "--password-stdin", "docker buildx build",
		"--build-arg COMMAND=", "--push", "docker buildx imagetools inspect", "web-app audit-collector",
		"Refusing to publish images from a dirty Git tree",
	} {
		if !strings.Contains(makeContent, required) {
			t.Errorf("Makefile container publication missing %q", required)
		}
	}
	if strings.Contains(makeContent, "DOCKER_TOKEN=") {
		t.Fatal("Makefile must not contain or default a registry token")
	}

	dockerfile, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerContent := string(dockerfile)
	for _, required := range []string{"--platform=$BUILDPLATFORM", "ARG TARGETOS", "ARG TARGETARCH", `GOOS="$TARGETOS" GOARCH="$TARGETARCH"`} {
		if !strings.Contains(dockerContent, required) {
			t.Errorf("Dockerfile cross-compilation missing %q", required)
		}
	}
}

func TestReviewedPublicationLockMatchesHelmValues(t *testing.T) {
	values, err := os.ReadFile("../deploy/helm/wai-strict/values-kubernetes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Resolve the publication record from the revision the reviewed values
	// declare, so republishing cannot leave the values pinned to one record
	// while this test still checks a stale one.
	revision := regexp.MustCompile(`(?m)^# Reviewed deployment input for source revision ([0-9a-f]{12})\.`).FindSubmatch(values)
	if revision == nil {
		t.Fatal("reviewed values must name the source revision they were published from")
	}
	lockBytes, err := os.ReadFile("../deploy/images/strict-" + string(revision[1]) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var lock publicationLock
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.SourceRevision != string(revision[1]) {
		t.Fatalf("publication record names revision %q but the reviewed values name %q", lock.SourceRevision, revision[1])
	}
	if err := validatePublicationLock(lock, string(values)); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"client-secret:", "password:", "private-key:", "dockerconfigjson", ":latest"} {
		if strings.Contains(strings.ToLower(string(values)), forbidden) {
			t.Fatalf("reviewed values contain secret or mutable material %q", forbidden)
		}
	}
}

func TestPublicationLockRejectsUnsafeInputs(t *testing.T) {
	valid := publicationLock{
		SourceRevision:    "revision",
		RequiredPlatforms: []string{"linux/amd64", "linux/arm64"},
		Images:            map[string]string{},
	}
	values := ""
	for _, name := range []string{"ttsAdapter", "gateway", "mcpServer", "api", "workbench", "auditCollector"} {
		valid.Images[name] = "docker.io/example/" + name + "@sha256:" + strings.Repeat("a", 64)
		values += "repository: docker.io/example/" + name + "\ndigest: \"sha256:" + strings.Repeat("a", 64) + "\"\n"
	}

	tests := []struct {
		name   string
		mutate func(publicationLock) (publicationLock, string)
	}{
		{"missing platform", func(lock publicationLock) (publicationLock, string) {
			lock.RequiredPlatforms = []string{"linux/amd64"}
			return lock, values
		}},
		{"mutable tag", func(lock publicationLock) (publicationLock, string) {
			lock.Images["gateway"] = "docker.io/example/gateway:latest"
			return lock, values
		}},
		{"missing image", func(lock publicationLock) (publicationLock, string) { delete(lock.Images, "api"); return lock, values }},
		{"digest mismatch", func(lock publicationLock) (publicationLock, string) {
			lock.Images["workbench"] = "docker.io/example/workbench@sha256:" + strings.Repeat("b", 64)
			return lock, values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyLock := valid
			copyLock.Images = make(map[string]string, len(valid.Images))
			for key, value := range valid.Images {
				copyLock.Images[key] = value
			}
			candidate, candidateValues := test.mutate(copyLock)
			if err := validatePublicationLock(candidate, candidateValues); err == nil {
				t.Fatal("unsafe publication input was accepted")
			}
		})
	}
}
