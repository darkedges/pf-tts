package authorization

import (
	"context"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
)

func TestStrictCallChainPolicyAllowsOnlyExactSignedProfile(t *testing.T) {
	policy, err := NewOPA(context.Background(), "../../config/authorization-strict.rego", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := identity.NewUserIdentity("user")
	agent, _ := identity.NewAgentIdentity("urn:agent:demo", "instance")
	workload, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	caller, _ := identity.NewWorkloadIdentity("spiffe://example.org/agent/demo")
	txn, _ := identity.NewTransactionIdentity("txn", "demo:system.whoami")
	auth, _ := identity.NewAuthorizationContext([]string{"mcp.system.whoami"})
	value, _ := identity.NewRequestIdentityContext(user, agent, workload, caller, txn, auth)
	if err := policy.Authorize(context.Background(), value, "demo", "system.whoami"); err != nil {
		t.Fatalf("exact strict policy tuple denied: %v", err)
	}
	for name, mutate := range map[string]func(*identity.RequestIdentityContext){
		"scope expansion": func(v *identity.RequestIdentityContext) {
			v.Authorization.Scope = append(v.Authorization.Scope, "admin")
		},
		"wrong purpose": func(v *identity.RequestIdentityContext) { v.Transaction.Purpose = "system.whoami" },
		"wrong workload": func(v *identity.RequestIdentityContext) {
			v.OriginalWorkload.SPIFFEID = "spiffe://example.org/agent/other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := value
			candidate.Authorization.Scope = append([]string(nil), value.Authorization.Scope...)
			mutate(&candidate)
			if err := policy.Authorize(context.Background(), candidate, "demo", "system.whoami"); err == nil {
				t.Fatal("expanded or mismatched strict policy tuple allowed")
			}
		})
	}
}
