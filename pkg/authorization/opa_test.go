package authorization

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
)

func TestOPAAllowsOnlyExactVerifiedInput(t *testing.T) {
	policy := newTestOPA(t, `package wai.authz
import rego.v1
default allow := false
allow if { input.agent_id == "urn:agent:demo"; input.workload_id == "spiffe://example.org/agent/demo"; input.purpose == "system.whoami"; input.target == "demo"; input.tool == "system.whoami"; "mcp:invoke" in input.scopes }`)
	value := requestIdentity(t)
	if err := policy.Authorize(context.Background(), value, "demo", "system.whoami"); err != nil {
		t.Fatalf("exact verified tuple denied: %v", err)
	}
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
		{"missing scope", func(v *identity.RequestIdentityContext) { v.Authorization.Scope = nil }, "demo", "system.whoami"},
		{"wrong target", func(*identity.RequestIdentityContext) {}, "admin", "system.whoami"},
		{"wrong tool", func(*identity.RequestIdentityContext) {}, "demo", "customer.get"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := requestIdentity(t)
			tt.mutate(&value)
			if err := policy.Authorize(context.Background(), value, tt.target, tt.tool); err == nil {
				t.Fatal("conflicting verified policy input accepted")
			}
		})
	}
}

func TestOPAFailsClosedForUndefinedNonBooleanAndCancelledDecisions(t *testing.T) {
	for name, module := range map[string]string{
		"undefined": `package wai.authz
import rego.v1
allow if { false }`,
		"non_boolean": `package wai.authz
allow := "yes"`,
	} {
		t.Run(name, func(t *testing.T) {
			policy := newTestOPA(t, module)
			if err := policy.Authorize(context.Background(), requestIdentity(t), "demo", "system.whoami"); err == nil {
				t.Fatal("ambiguous OPA decision accepted")
			}
		})
	}
	policy := newTestOPA(t, `package wai.authz
allow := true`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := policy.Authorize(ctx, requestIdentity(t), "demo", "system.whoami"); err == nil {
		t.Fatal("cancelled policy evaluation accepted")
	}
}

func TestOPARejectsInvalidPolicyAndNetworkBuiltins(t *testing.T) {
	for name, module := range map[string]string{
		"invalid": `package wai.authz
allow if {`,
		"network": `package wai.authz
import rego.v1
allow if { http.send({"method": "get", "url": "https://example.com"}) }`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writePolicy(t, module)
			if _, err := NewOPA(context.Background(), path, time.Second); err == nil {
				t.Fatal("unsafe OPA policy compiled")
			}
		})
	}
}

func newTestOPA(t *testing.T, module string) *OPA {
	t.Helper()
	policy, err := NewOPA(context.Background(), writePolicy(t, module), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func writePolicy(t *testing.T, module string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorization.rego")
	if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
