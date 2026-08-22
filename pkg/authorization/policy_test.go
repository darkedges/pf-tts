package authorization

import (
	"context"
	"os"
	"strings"
	"testing"

	"example.com/workload-agent-identity/pkg/identity"
)

func TestRepositoryJSONPolicyBindsWebAgentToExactWorkload(t *testing.T) {
	file, err := os.Open("../../config/authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	policy, err := LoadJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	value := requestIdentity(t)
	value.Agent.ID = "urn:agent:web-app"
	value.OriginalWorkload.SPIFFEID = "spiffe://example.org/agent/web-app"
	if err := policy.Authorize(context.Background(), value, "demo", "system.whoami"); err != nil {
		t.Fatalf("exact web workload binding denied: %v", err)
	}
	value.Agent.ID = "urn:agent:demo"
	if err := policy.Authorize(context.Background(), value, "demo", "system.whoami"); err == nil {
		t.Fatal("demo AgentID accepted over the web workload identity")
	}
}

const validPolicy = `{"rules":[{"agent_id":"urn:agent:demo","workload_id":"spiffe://example.org/agent/demo","purposes":["system.whoami"],"scopes":["mcp:invoke"],"target":"demo","tools":["system.whoami"]}]}`

func requestIdentity(t *testing.T) identity.RequestIdentityContext {
	t.Helper()
	user, _ := identity.NewUserIdentity("user")
	agent, _ := identity.NewAgentIdentity("urn:agent:demo", "instance")
	workload, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	caller, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	txn, _ := identity.NewTransactionIdentity("tx", "system.whoami")
	auth, _ := identity.NewAuthorizationContext([]string{"mcp:invoke"})
	value, _ := identity.NewRequestIdentityContext(user, agent, workload, caller, txn, auth)
	return value
}

func TestPolicyAllowsExactVerifiedTuple(t *testing.T) {
	policy, err := LoadJSON(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Authorize(context.Background(), requestIdentity(t), "demo", "system.whoami"); err != nil {
		t.Fatalf("exact trusted tuple denied: %v", err)
	}
}

func TestPolicyDeniesEveryConflictingIdentityDimension(t *testing.T) {
	policy, _ := LoadJSON(strings.NewReader(validPolicy))
	tests := []struct {
		name   string
		mutate func(*identity.RequestIdentityContext)
		target string
		tool   string
	}{
		{"forged agent", func(v *identity.RequestIdentityContext) { v.Agent.ID = "urn:agent:forged" }, "demo", "system.whoami"},
		{"wrong workload", func(v *identity.RequestIdentityContext) {
			v.OriginalWorkload.SPIFFEID = "spiffe://example.org/agent/other"
		}, "demo", "system.whoami"},
		{"wrong purpose", func(v *identity.RequestIdentityContext) { v.Transaction.Purpose = "customer.delete" }, "demo", "system.whoami"},
		{"missing scope", func(v *identity.RequestIdentityContext) { v.Authorization.Scope = []string{"other"} }, "demo", "system.whoami"},
		{"wrong target", func(*identity.RequestIdentityContext) {}, "admin", "system.whoami"},
		{"unapproved tool", func(*identity.RequestIdentityContext) {}, "demo", "admin.delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := requestIdentity(t)
			tt.mutate(&value)
			if err := policy.Authorize(context.Background(), value, tt.target, tt.tool); err == nil {
				t.Fatal("conflicting authorization tuple accepted")
			}
		})
	}
}

func TestPolicyRejectsAmbiguousAndUnknownConfiguration(t *testing.T) {
	duplicate := `{"rules":[` + strings.TrimPrefix(strings.TrimSuffix(validPolicy, "]}"), `{"rules":[`) + `,` + strings.TrimPrefix(strings.TrimSuffix(validPolicy, "]}"), `{"rules":[`) + `]}`
	for _, raw := range []string{duplicate, `{"rules":[],"unknown":true}`, `{"rules":[]}`} {
		if _, err := LoadJSON(strings.NewReader(raw)); err == nil {
			t.Fatalf("unsafe policy accepted: %s", raw)
		}
	}
}
