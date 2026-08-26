package pingauthorize_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type packageNode struct {
	Class                 string   `json:"class"`
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	RootEntityName        string   `json:"rootEntityName"`
	Operator              string   `json:"operator"`
	LHSInputNode          string   `json:"lhsInputNode"`
	RHSInputNode          string   `json:"rhsInputNode"`
	AttributeDefinitionID string   `json:"attributeDefinitionId"`
	Constant              string   `json:"constant"`
	InputNode             string   `json:"inputNode"`
	InputNodes            []string `json:"inputNodes"`
	Effect                string   `json:"effect"`
	Domains               []string `json:"domains"`
	Services              []string `json:"services"`
	Actions               []string `json:"actions"`
}

func TestDeploymentPackagePreservesExactSecurityBindings(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("policies", "wai-mcp-authorization.deploymentpackage"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDeploymentPackage(data); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentPackageValidationRejectsSecurityBindingDrift(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("policies", "wai-mcp-authorization.deploymentpackage"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		old  string
		new  string
	}{
		{"forged agent", "urn:agent:web-app", "urn:agent:forged"},
		{"wrong workload", "spiffe://example.org/agent/web-app", "spiffe://example.org/agent/other"},
		{"missing caller binding", `"name":"immediate_caller_id"`, `"name":"untrusted_caller"`},
		{"wrong purpose", "system.whoami", "customer.get"},
		{"missing scope", "mcp:invoke", ""},
		{"wrong target", `"domains":["WAI"]`, `"domains":["Other"]`},
		{"wrong action", `"actions":["Invoke"]`, `"actions":["Delete"]`},
		// The strict chain sends the signed route as the purpose and the strict
		// scope. A package carrying the non-strict spellings permits nothing on
		// that chain, which is the defect this rule set exists to prevent.
		{"strict purpose reverted to the bare tool", `"constant":"demo:system.whoami"`, `"constant":"system.whoami"`},
		{"strict scope reverted to the coarse scope", `"constant":"mcp.system.whoami"`, `"constant":"mcp:invoke"`},
		{"strict agent binding widened", "urn:agent:demo", "urn:agent:any"},
		{"conjunction weakened to a disjunction", `"operator":"and"`, `"operator":"or"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := []byte(stringReplaceOnce(string(data), test.old, test.new))
			if err := validateDeploymentPackage(mutated); err == nil {
				t.Fatal("unsafe deployment package drift was accepted")
			}
		})
	}
}

// reviewedTuples are the only decisions this package may permit. Each is an
// exact tuple: a request matches only when every attribute equals its constant.
//
// The strict call chain synthesises the purpose from the signed route as
// "<target>:<tool>" and carries the strict scope; the non-strict chain carries
// the bare tool name and mcp:invoke. Both appear here because one package serves
// both. A tuple that mixed them would permit nothing, which is how the strict
// chain would silently fail closed.
func reviewedTuples() []map[string]string {
	return []map[string]string{
		{
			"agent_id": "urn:agent:web-app", "workload_id": "spiffe://example.org/agent/web-app",
			"immediate_caller_id": "spiffe://example.org/agent/web-app",
			"purpose":             "system.whoami", "scope": "mcp:invoke", "target": "demo", "tool": "system.whoami",
		},
		{
			"agent_id": "urn:agent:web-app", "workload_id": "spiffe://example.org/agent/web-app",
			"immediate_caller_id": "spiffe://example.org/agent/web-app",
			"purpose":             "demo:system.whoami", "scope": "mcp.system.whoami", "target": "demo", "tool": "system.whoami",
		},
		{
			"agent_id": "urn:agent:demo", "workload_id": "spiffe://example.org/agent/demo",
			"immediate_caller_id": "spiffe://example.org/agent/demo",
			"purpose":             "demo:system.whoami", "scope": "mcp.system.whoami", "target": "demo", "tool": "system.whoami",
		},
	}
}

func validateDeploymentPackage(data []byte) error {
	var nodes []packageNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return fmt.Errorf("parse deployment package: %w", err)
	}
	attributes := map[string]string{}
	attributeNodes := map[string]string{}
	constants := map[string]string{}
	comparisons := map[string][2]string{}
	booleanNodes := map[string]packageNode{}
	var decisions []packageNode
	var targets []packageNode
	rootName := ""
	for _, node := range nodes {
		switch node.Class {
		case "Package":
			rootName = node.RootEntityName
		case "AttributeDefinition":
			attributes[node.ID] = node.Name
		case "AttributeNode":
			attributeNodes[node.ID] = node.AttributeDefinitionID
		case "ConstantNode":
			constants[node.ID] = node.Constant
		case "ComparisonNode":
			if node.Operator != "EQUALS" {
				return fmt.Errorf("comparison %s does not use EQUALS", node.ID)
			}
			comparisons[node.ID] = [2]string{node.LHSInputNode, node.RHSInputNode}
		case "BooleanLogicNode":
			booleanNodes[node.ID] = node
		case "DecisionNode":
			decisions = append(decisions, node)
		case "Target":
			targets = append(targets, node)
		}
	}
	if rootName != "WAI MCP Decisions" {
		return fmt.Errorf("unexpected root policy %q", rootName)
	}

	expected := reviewedTuples()
	if len(decisions) != len(expected) {
		return fmt.Errorf("found %d decisions, expected %d reviewed rules", len(decisions), len(expected))
	}

	// Resolve each PERMIT back to the tuple it actually enforces, rather than
	// counting matching comparisons. Counting cannot tell one rule's bindings
	// from another's once the package holds more than one rule.
	var enforced []map[string]string
	for _, decision := range decisions {
		if decision.Effect != "PERMIT" {
			return fmt.Errorf("decision %s is not an explicit PERMIT", decision.ID)
		}
		logic, ok := booleanNodes[decision.InputNode]
		if !ok || logic.Operator != "and" {
			return fmt.Errorf("decision %s is not guarded by a conjunction", decision.ID)
		}
		tuple := map[string]string{}
		for _, id := range logic.InputNodes {
			endpoints, ok := comparisons[id]
			if !ok {
				return fmt.Errorf("decision %s is guarded by a non-comparison node", decision.ID)
			}
			name := attributes[attributeNodes[endpoints[0]]]
			value, known := constants[endpoints[1]]
			if name == "" || !known {
				return fmt.Errorf("decision %s compares an unresolved attribute or constant", decision.ID)
			}
			if _, duplicate := tuple[name]; duplicate {
				return fmt.Errorf("decision %s binds %s more than once", decision.ID, name)
			}
			tuple[name] = value
		}
		enforced = append(enforced, tuple)
	}

	for _, want := range expected {
		if !containsTuple(enforced, want) {
			return fmt.Errorf("no PERMIT is guarded by the reviewed tuple %v", want)
		}
	}
	for _, got := range enforced {
		if !containsTuple(expected, got) {
			return fmt.Errorf("the package permits an unreviewed tuple %v", got)
		}
	}

	if len(targets) != 1 || !slices.Equal(targets[0].Domains, []string{"WAI"}) || !slices.Equal(targets[0].Services, []string{"WAI MCP"}) || !slices.Equal(targets[0].Actions, []string{"Invoke"}) {
		return fmt.Errorf("unexpected policy target")
	}
	return nil
}

func containsTuple(set []map[string]string, want map[string]string) bool {
	for _, candidate := range set {
		if len(candidate) != len(want) {
			continue
		}
		match := true
		for name, value := range want {
			if candidate[name] != value {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func stringReplaceOnce(value, old, replacement string) string {
	for i := 0; i+len(old) <= len(value); i++ {
		if value[i:i+len(old)] == old {
			return value[:i] + replacement + value[i+len(old):]
		}
	}
	return value
}

// The testdata files are the request bodies used to exercise a running decision
// point. They are only meaningful if each permit case actually matches a rule in
// the committed package and each deny case actually matches none, so check them
// against the package rather than trusting their filenames.
func TestDecisionTestdataAgreesWithTheCommittedPackage(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	reviewed := reviewedTuples()
	guarded := []string{"agent_id", "workload_id", "immediate_caller_id", "purpose", "scope", "target", "tool"}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		seen++
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var request struct {
				Domain     string            `json:"domain"`
				Service    string            `json:"service"`
				Action     string            `json:"action"`
				Attributes map[string]string `json:"attributes"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatal(err)
			}
			if request.Domain != "WAI" || request.Service != "WAI MCP" || request.Action != "Invoke" {
				t.Fatalf("%s is not targeted at the reviewed decision", name)
			}
			// The adapter requires these regardless of the policy, so a case
			// missing one would be denied for the wrong reason.
			for _, required := range []string{"user_id", "agent_instance_id", "transaction_id"} {
				if strings.TrimSpace(request.Attributes[required]) == "" {
					t.Errorf("%s omits %s, which the adapter requires", name, required)
				}
			}
			tuple := map[string]string{}
			for _, key := range guarded {
				tuple[key] = request.Attributes[key]
			}
			matches := containsTuple(reviewed, tuple)
			shouldPermit := strings.HasPrefix(name, "permit-")
			if matches != shouldPermit {
				t.Fatalf("%s: package match=%v but the filename claims permit=%v", name, matches, shouldPermit)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no decision testdata was found")
	}
}

// The package is generated from a reviewed rule set. If someone edits the JSON
// by hand the generator and the artefact drift apart, so prove they agree.
func TestCommittedPackageMatchesTheGenerator(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("python is not available to run the package generator")
	}
	command := exec.Command("python", filepath.Join("scripts", "build_policy_package.py"), "--check")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the committed package is out of step with the reviewed rules: %s", output)
	}
}
