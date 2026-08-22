package spirelab

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, path ...string) string {
	t.Helper()
	parts := append([]string{"..", ".."}, path...)
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLabUsesDistinctExternallyAttestedWorkloadSelectors(t *testing.T) {
	script := readRepoFile(t, "scripts", "spire-register.sh")
	want := []string{
		`"spiffe://example.org/agent/demo"`, `"docker:label:wai.workload:demo-agent"`,
		`"spiffe://example.org/gateway/mcp"`, `"docker:label:wai.workload:mcp-gateway"`,
		`"spiffe://example.org/mcp/demo"`, `"docker:label:wai.workload:demo-mcp-server"`,
		`"spiffe://example.org/api/demo"`, `"docker:label:wai.workload:demo-api"`,
	}
	for _, value := range want {
		if !strings.Contains(script, value) {
			t.Errorf("registration is missing %s", value)
		}
	}
	if strings.Count(script, "docker:label:wai.workload:") != 4 {
		t.Fatal("each lab workload must have one distinct Docker-attested selector")
	}
}

func TestRegistrationRejectsSharedWorkloadIdentityConfiguration(t *testing.T) {
	script := readRepoFile(t, "scripts", "spire-register.sh")
	matches := regexp.MustCompile(`create_entry "([^"]+)"\s+\\?\s*\n?\s*"([^"]+)"`).FindAllStringSubmatch(script, -1)
	if len(matches) != 4 {
		t.Fatalf("expected exactly four workload registrations, got %d", len(matches))
	}
	spiffeIDs := make(map[string]struct{}, len(matches))
	selectors := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if _, duplicate := spiffeIDs[match[1]]; duplicate {
			t.Fatalf("multiple workloads must not share SPIFFE ID %q", match[1])
		}
		if _, duplicate := selectors[match[2]]; duplicate {
			t.Fatalf("multiple SPIFFE IDs must not share selector %q", match[2])
		}
		spiffeIDs[match[1]] = struct{}{}
		selectors[match[2]] = struct{}{}
	}
}

func TestProbeRequiresActorAudienceAndLabel(t *testing.T) {
	compose := readRepoFile(t, "deploy", "spire", "compose.yaml")
	for _, required := range []string{"wai.workload: demo-agent", "urn:pingfederate:wai:token-exchange", "/run/spire/sockets/agent.sock"} {
		if !strings.Contains(compose, required) {
			t.Errorf("probe missing required binding %q", required)
		}
	}
}

func TestProbeDoesNotLogRawJWTSVID(t *testing.T) {
	script := readRepoFile(t, "scripts", "spire-test-jwt.sh")
	for _, required := range []string{`RESPONSE="$(docker compose`, `trap 'unset RESPONSE' EXIT`, `print(f"JWT-SVID obtained: subject=`} {
		if !strings.Contains(script, required) {
			t.Fatalf("safe probe handling missing %q", required)
		}
	}
	if strings.Contains(script, `echo "$RESPONSE"`) {
		t.Fatal("probe must not print the raw SPIRE CLI response")
	}
}

func TestServerDoesNotPublishAnUnneededHostPort(t *testing.T) {
	compose := readRepoFile(t, "deploy", "spire", "compose.yaml")
	if strings.Contains(compose, `"127.0.0.1:8081:8081"`) {
		t.Fatal("the repository-owned lab must not conflict with an unrelated host service")
	}
}

func TestBootstrapSecretsAreNotCommitted(t *testing.T) {
	compose := readRepoFile(t, "deploy", "spire", "compose.yaml")
	if strings.Contains(compose, "SPIRE_JOIN_TOKEN=") {
		t.Fatal("compose must not contain a join token value")
	}
	if strings.Contains(compose, "SPIRE_JOIN_TOKEN:?") {
		t.Fatal("required interpolation prevents the server-only token bootstrap phase")
	}
	bootstrap := readRepoFile(t, "scripts", "spire-lab-up.sh")
	if !strings.Contains(bootstrap, `if [[ -z "${SPIRE_JOIN_TOKEN}" ]]`) {
		t.Fatal("bootstrap must fail before starting the agent when token generation returns empty")
	}
	if strings.Contains(bootstrap, `token generate -spiffeID`) {
		t.Fatal("bootstrap must not force a caller-chosen identity into SPIRE's reserved agent namespace")
	}
	if strings.Contains(bootstrap, `> "$GENERATED/join-token"`) {
		t.Fatal("bootstrap must never persist the join token")
	}
	if !strings.Contains(bootstrap, `"${#AGENT_IDS[@]}" -ne 1`) || !strings.Contains(bootstrap, "Expected exactly one unambiguous join-token agent identity") {
		t.Fatal("bootstrap must reject ambiguous or unexpected attested agent identities")
	}
	if !strings.Contains(bootstrap, `awk '/^SPIFFE ID/ {print $4}'`) {
		t.Fatal("bootstrap must extract the SPIFFE ID value, not the output separator")
	}
	ignore := readRepoFile(t, ".gitignore")
	if !strings.Contains(ignore, "deploy/spire/generated/*") {
		t.Fatal("generated bootstrap material is not ignored")
	}
}

func TestRegistrationRejectsMissingOrUnexpectedAttestedParent(t *testing.T) {
	script := readRepoFile(t, "scripts", "spire-register.sh")
	for _, required := range []string{"[[ ! -s \"$GENERATED/agent-id\" ]]", "Refusing unexpected SPIRE agent parent ID", "spiffe://example\\.org/spire/agent/join_token/"} {
		if !strings.Contains(script, required) {
			t.Fatalf("registration parent validation missing %q", required)
		}
	}
}

func TestRegistrationReplacesStaleParentAndRejectsAmbiguity(t *testing.T) {
	script := readRepoFile(t, "scripts", "spire-register.sh")
	for _, required := range []string{
		`awk '/^Entry ID/ {print $4}'`,
		`awk '/^Parent ID/ {print $4}'`,
		`"${#entry_ids[@]}" -gt 1`,
		"Refusing ambiguous existing registration",
		`"${parent_ids[0]}" == "$PARENT"`,
		`entry delete -entryID "${entry_ids[0]}"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("registration stale-parent handling missing %q", required)
		}
	}
}

func TestRepositoryGuidanceUsesAttestorDerivedParentIdentity(t *testing.T) {
	guidance := readRepoFile(t, "AGENTS.md")
	if strings.Contains(guidance, "spiffe://example.org/spire/agent/local-lab") {
		t.Fatal("repository guidance must not require a caller-forced ID in SPIRE's reserved agent namespace")
	}
	for _, required := range []string{"spiffe://example.org/spire/agent/join_token/<one-time-token-id>", "must never persist the join token", "reject missing"} {
		if !strings.Contains(guidance, required) {
			t.Fatalf("repository guidance missing parent-identity rule %q", required)
		}
	}
}

func TestJoinTokenIsDocumentedAsLabOnly(t *testing.T) {
	docs := strings.ToLower(readRepoFile(t, "docs", "spire-lab.md"))
	if !strings.Contains(docs, "join_token") || !strings.Contains(docs, "only") || !strings.Contains(docs, "production") {
		t.Fatal("join-token trust limitation must be explicit")
	}
}

func TestElevatedContainerPrivilegeIsDocumentedAsLabOnly(t *testing.T) {
	docs := strings.ToLower(readRepoFile(t, "docs", "spire-lab.md"))
	for _, warning := range []string{"runs its spire containers as root", "host pid namespace", "local-lab accommodations", "production deployment recommendation"} {
		if !strings.Contains(docs, warning) {
			t.Fatalf("missing elevated-privilege warning %q", warning)
		}
	}
}
