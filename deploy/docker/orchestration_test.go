package dockerlab

import (
	"os"
	"strings"
	"testing"
)

func TestComposeProfilesAndIdentityIsolation(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, required := range []string{`profiles: ["app-only", "local-lab"]`, `profiles: ["local-lab"]`, "wai.workload: mcp-gateway", "wai.workload: demo-mcp-server", "wai.workload: demo-api", "wai.workload: demo-agent"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("orchestration missing %q", required)
		}
	}
	if !strings.Contains(compose, "${SPIRE_SOCKET_VOLUME:-spire_spire-agent-socket}") {
		t.Fatal("application profile must default to the repository SPIRE Compose socket volume")
	}
	if strings.Count(compose, "wai.workload:") != 4 {
		t.Fatal("each demo workload must have exactly one distinct attested label")
	}
}

func TestComposeDoesNotContainCredentialValues(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, forbidden := range []string{"2FederateM0re", "Bearer eyJ", "client_secret:"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("Compose contains credential material %q", forbidden)
		}
	}
	for _, required := range []string{"${PF_CLIENT_SECRET:?", "${USER_ACCESS_TOKEN:-}"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("secret must be externally injected using %q", required)
		}
	}
	for _, required := range []string{"PF_CA_FILE: /run/pingfederate/ca.pem", "local-runtime-ca.pem:/run/pingfederate/ca.pem:ro"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("PingFederate trust anchor must be explicitly mounted using %q", required)
		}
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "PF_ADMIN_INSECURE"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("application Compose must not disable TLS validation using %q", forbidden)
		}
	}
}

func TestLiveLabCoversFailureBoundariesWithoutTokenOutput(t *testing.T) {
	b, err := os.ReadFile("run_live_lab.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{`agent("normal", True)`, `agent("spoof-agent", False)`, `agent("wrong-audience", False)`, `agent("expired-token", False)`, `agent("unapproved-mcp", False)`, `agent("direct-to-api", False)`, `ssl.create_default_context(cafile=`} {
		if !strings.Contains(script, required) {
			t.Fatalf("live lab missing security failure case %q", required)
		}
	}
	for _, forbidden := range []string{"print(subject_token)", "write_text", "CERT_NONE", "check_hostname = False"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("live lab weakens validation or persists a token using %q", forbidden)
		}
	}
}
