package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pingAuthorizeChart(t *testing.T) string {
	t.Helper()
	var content strings.Builder
	err := filepath.Walk("../deploy/helm/wai-pingauthorize", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		// The reviewed policy package is a large single-line artefact with its
		// own test; including it here would only make every substring check
		// noisier.
		if strings.HasSuffix(path, ".deploymentpackage") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content.Write(data)
		content.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return content.String()
}

func TestPingAuthorizeDecisionPointIsIsolatedPinnedAndFailClosed(t *testing.T) {
	chart := pingAuthorizeChart(t)
	for _, required := range []string{
		"kind: StatefulSet", "volumeClaimTemplates:", "mountPath: /opt/out",
		"kind: PodDisruptionBudget", "kind: NetworkPolicy", "podSelector: {}", "type: ClusterIP",
		"automountServiceAccountToken: false", "runAsNonRoot: true", "allowPrivilegeEscalation: false",
		`capabilities: {drop: ["ALL"]}`, "readOnlyRootFilesystem: true",
		"startupProbe:", "readinessProbe:", "livenessProbe:",
		"docker.io/pingidentity/pingauthorize@sha256:", "PING_IDENTITY_ACCEPT_EULA",
		"valueFrom: {secretKeyRef:",
		// The serving identity is supplied, not self-signed.
		"KEYSTORE_FILE", "KEYSTORE_TYPE", "TRUSTSTORE_FILE", "wai-pa11-runtime-tls",
		// The overlay must be materialised as real files, or the vendor's
		// permissive sample policy silently stays in force.
		"/writable-profile/pd.profile/dsconfig/30-wai-mcp-policy.dsconfig",
		"deployment-package</run/wai/wai-mcp-authorization.deploymentpackage",
		"skipTLSVerify: false", "method: kubernetes",
	} {
		if !strings.Contains(chart, required) {
			t.Errorf("isolated decision point missing control %q", required)
		}
	}
	for _, forbidden := range []string{
		"kind: Ingress", "type: LoadBalancer", "type: NodePort", ":latest", ":edge",
		"kind: Secret", "stringData:", "vaultToken", "method: appRole", "skipTLSVerify: true",
		"automountServiceAccountToken: true", "privileged: true", "hostPath:",
		"envFrom:", "2FederateM0re", "tls.key\"", "-----BEGIN",
		// The LDAP port is never published.
		"port: 1389", "containerPort: 1389",
	} {
		if strings.Contains(chart, forbidden) {
			t.Errorf("isolated decision point crosses a security boundary with %q", forbidden)
		}
	}

	// The init container and the product must share one digest-pinned image, so
	// nothing else can be introduced while preparing the profile.
	statefulSet, err := os.ReadFile("../deploy/helm/wai-pingauthorize/templates/statefulset.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if references := strings.Count(string(statefulSet), ".Values.images.runtime"); references != 2 {
		t.Errorf("expected the same pinned image for the init and product containers, found %d references", references)
	}
}

func TestPingAuthorizeVaultPolicyAndRoleAreExact(t *testing.T) {
	policyBytes, err := os.ReadFile("../deploy/vault/wai-pingauthorize-11-1-policy.hcl")
	if err != nil {
		t.Fatal(err)
	}
	policy := string(policyBytes)
	if strings.Contains(policy, "*") || strings.Contains(policy, `capabilities = ["create"`) || strings.Contains(policy, `capabilities = ["list"`) {
		t.Fatal("the isolated decision point policy must be exact and read-only")
	}
	reviewed := []string{"administrator", "devops", "runtime-tls", "runtime-ca"}
	if strings.Count(policy, `capabilities = ["read"]`) != len(reviewed) {
		t.Fatalf("the policy must expose exactly %d reviewed records", len(reviewed))
	}
	for _, record := range reviewed {
		if !strings.Contains(policy, `path "kv/data/wai/pingauthorize-11-1/`+record+`" { capabilities = ["read"] }`) {
			t.Errorf("the policy is missing the reviewed read-only record %q", record)
		}
	}

	// The gateway verifies the decision point; it must never be able to
	// impersonate it, so the key pair is out of reach.
	strictBytes, err := os.ReadFile("../deploy/vault/wai-strict-policy.hcl")
	if err != nil {
		t.Fatal(err)
	}
	strict := string(strictBytes)
	if !strings.Contains(strict, "kv/data/wai/pingauthorize-11-1/runtime-ca") {
		t.Error("the strict policy cannot read the decision point's public certificate")
	}
	if strings.Contains(strict, "kv/data/wai/pingauthorize-11-1/runtime-tls") {
		t.Error("the strict policy reaches the decision point's private key")
	}

	roleBytes, err := os.ReadFile("../deploy/vault/wai-pingauthorize-11-1-kubernetes-role.json")
	if err != nil {
		t.Fatal(err)
	}
	var role struct {
		Names      []string `json:"bound_service_account_names"`
		Namespaces []string `json:"bound_service_account_namespaces"`
		Policies   []string `json:"token_policies"`
		Audience   string   `json:"audience"`
		TTL        string   `json:"token_ttl"`
	}
	if err := json.Unmarshal(roleBytes, &role); err != nil {
		t.Fatal(err)
	}
	if len(role.Names) != 1 || role.Names[0] != "wai-pingauthorize-vault-auth" ||
		len(role.Namespaces) != 1 || role.Namespaces[0] != "wai-pingauthorize" ||
		len(role.Policies) != 1 || role.Policies[0] != "wai-pingauthorize-11-1" ||
		role.Audience != "vault" || role.TTL == "" {
		t.Fatalf("the Kubernetes role is not bound to exactly the reviewed identity: %+v", role)
	}
}

func TestStrictChartKeepsOPADefaultAndBoundsTheDecisionPoint(t *testing.T) {
	values, err := os.ReadFile("../deploy/helm/wai-strict/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(values), "provider: opa") {
		t.Error("the strict chart must default to the reviewed rego policy")
	}

	schema, err := os.ReadFile("../deploy/helm/wai-strict/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	allowlist := string(schema)
	for _, required := range []string{
		`"provider": {"enum": ["opa", "pingauthorize"]}`,
		`"url": {"const": "https://wai-pingauthorize.wai-pingauthorize.svc.cluster.local:1443/governance-engine"}`,
		`"port": {"const": 1443}`,
	} {
		if !strings.Contains(allowlist, required) {
			t.Errorf("the decision point is not bounded by the schema: missing %q", required)
		}
	}

	// The endpoint the adapter accepts is exact. A schema that allowed any URL
	// would let a deployment point the gateway at another decision point.
	policy, err := os.ReadFile("../deploy/helm/wai-strict/templates/networkpolicy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policy), ".Values.authorization.pingAuthorize.namespace") {
		t.Error("egress to the decision point is not a named, narrow rule")
	}
	if strings.Contains(string(policy), "port: 443\n") {
		t.Error("blanket 443 egress was reinstated")
	}
}
