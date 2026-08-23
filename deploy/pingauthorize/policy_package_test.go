package pingauthorize_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := []byte(stringReplaceOnce(string(data), test.old, test.new))
			if err := validateDeploymentPackage(mutated); err == nil {
				t.Fatal("unsafe deployment package drift was accepted")
			}
		})
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
	var booleanNodes []packageNode
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
			booleanNodes = append(booleanNodes, node)
		case "DecisionNode":
			decisions = append(decisions, node)
		case "Target":
			targets = append(targets, node)
		}
	}
	if rootName != "WAI MCP Decisions" {
		return fmt.Errorf("unexpected root policy %q", rootName)
	}
	expected := map[string]string{
		"agent_id":            "urn:agent:web-app",
		"workload_id":         "spiffe://example.org/agent/web-app",
		"immediate_caller_id": "spiffe://example.org/agent/web-app",
		"purpose":             "system.whoami",
		"scope":               "mcp:invoke",
		"target":              "demo",
		"tool":                "system.whoami",
	}
	comparisonIDs := make([]string, 0, len(expected))
	for id, endpoints := range comparisons {
		name := attributes[attributeNodes[endpoints[0]]]
		if want, ok := expected[name]; ok && constants[endpoints[1]] == want {
			comparisonIDs = append(comparisonIDs, id)
		}
	}
	if len(comparisonIDs) != len(expected) {
		return fmt.Errorf("found %d of %d exact security bindings", len(comparisonIDs), len(expected))
	}
	if len(decisions) != 1 || decisions[0].Effect != "PERMIT" {
		return fmt.Errorf("expected one explicit PERMIT decision")
	}
	guarded := false
	for _, node := range booleanNodes {
		if node.Operator == "and" && len(node.InputNodes) == len(comparisonIDs) && sameStrings(node.InputNodes, comparisonIDs) && decisions[0].InputNode == node.ID {
			guarded = true
		}
	}
	if !guarded {
		return fmt.Errorf("PERMIT is not guarded by all exact security bindings")
	}
	if len(targets) != 1 || !slices.Equal(targets[0].Domains, []string{"WAI"}) || !slices.Equal(targets[0].Services, []string{"WAI MCP"}) || !slices.Equal(targets[0].Actions, []string{"Invoke"}) {
		return fmt.Errorf("unexpected policy target")
	}
	return nil
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
