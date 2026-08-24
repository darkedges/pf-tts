package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pf13Chart(t *testing.T) string {
	t.Helper()
	var content strings.Builder
	err := filepath.Walk("../deploy/helm/wai-pingfederate", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
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

func TestPingFederate13RuntimeIsIsolatedPinnedAndFailClosed(t *testing.T) {
	chart := pf13Chart(t)
	for _, required := range []string{
		"kind: StatefulSet", "volumeClaimTemplates:", "name: out-pf13-profile", "mountPath: /opt/out",
		"kind: PodDisruptionBudget", "kind: NetworkPolicy", "podSelector: {}", "type: ClusterIP",
		"automountServiceAccountToken: false", "runAsNonRoot: true", "allowPrivilegeEscalation: false",
		`capabilities: {drop: ["ALL"]}`, "readOnlyRootFilesystem: true", "startupProbe:", "readinessProbe:", "livenessProbe:",
		"docker.io/darkedges/pf-tts-pingfederate@sha256:c0871f8ccfcf4b4ef28200d2ce9a1b65a979b83a35e2654669b19383b38c0bd9",
		"PING_IDENTITY_ACCEPT_EULA", "ORCHESTRATION_TYPE", "valueFrom: {secretKeyRef:",
		"cp -R /opt/staging/. /writable-staging/", "mountPath: /etc/motd, subPath: motd",
		"secretName: wai-pf13-runtime-ca, defaultMode: 256", "wai-pingfederate-vault-auth",
	} {
		if !strings.Contains(chart, required) {
			t.Errorf("isolated runtime missing control %q", required)
		}
	}
	for _, forbidden := range []string{
		"kind: Ingress", "type: LoadBalancer", "type: NodePort", ":latest", ":edge", "namespace: pingfed",
		"id.ping.darkedges.com", "skipTLSVerify: true", "kind: Secret", "stringData:", "vaultToken",
		"method: appRole", "automountServiceAccountToken: true", "privileged: true", "hostPath:",
		"forgerock-vault-tls", "tls.key", "fetch-profile", "assemble-profile", "crane@sha256", "mountPath: /opt/in",
	} {
		if strings.Contains(chart, forbidden) {
			t.Errorf("isolated runtime crosses a security boundary with %q", forbidden)
		}
	}
}

func TestPingFederate13RuntimeRejectsMutableOrWritableSecretInputs(t *testing.T) {
	chart := pf13Chart(t)
	if strings.Count(chart, "images.runtime") != 2 {
		t.Fatalf("expected the same baked runtime for init and product containers")
	}
	for _, key := range []string{"provisioner-password", "ssl-file-data", "ssl-password", "current-system-key", "pending-system-key"} {
		if !strings.Contains(chart, "key: "+key) {
			t.Errorf("missing exact fail-closed bootstrap key %q", key)
		}
	}
	if strings.Contains(chart, "envFrom:") {
		t.Fatal("broad secret import could expose unreviewed Vault fields")
	}
	values, err := os.ReadFile("../deploy/helm/wai-pingfederate/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(values), "\n") {
		if strings.Contains(line, "runtime:") && !strings.Contains(line, "@sha256:") {
			t.Fatalf("runtime is mutable: %s", line)
		}
	}
}

func TestRepositoryPingFederateProfileStagesOnlyBakedPlugin(t *testing.T) {
	profile, err := os.ReadFile("../profiles/pingfederate/hooks/02-get-remote-server-profile.sh.post")
	if err != nil {
		t.Fatal(err)
	}
	content := string(profile)
	for _, required := range []string{
		"/opt/staging/wai-pingfederate-spiffe-plugins.jar", "/opt/staging/instance/server/default/deploy",
		`[ ! -f "${source_jar}" ]`, `[ -L "${source_jar}" ]`, `install -d -m 0550`, `install -m 0444`,
	} {
		if !strings.Contains(content, required) {
			t.Errorf("repository profile missing fail-closed staging control %q", required)
		}
	}
	for _, forbidden := range []string{
		"env_vars", "bulk-config", "curl ", "wget ", "-----BEGIN", "2FederateM0re", "secretpass",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("repository profile contains forbidden input %q", forbidden)
		}
	}
}
