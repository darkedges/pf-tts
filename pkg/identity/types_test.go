package identity

import "testing"

func TestIdentityConstructorsRejectInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{"empty user", func() error { _, err := NewUserIdentity(" "); return err }},
		{"empty agent", func() error { _, err := NewAgentIdentity("", "instance"); return err }},
		{"empty agent instance", func() error { _, err := NewAgentIdentity("agent", ""); return err }},
		{"non SPIFFE workload", func() error { _, err := NewWorkloadIdentity("agent"); return err }},
		{"empty SPIFFE authority", func() error { _, err := NewWorkloadIdentity("spiffe://"); return err }},
		{"empty transaction", func() error { _, err := NewTransactionIdentity("", "purpose"); return err }},
		{"empty purpose", func() error { _, err := NewTransactionIdentity("tx", ""); return err }},
		{"empty scopes", func() error { _, err := NewAuthorizationContext(nil); return err }},
		{"blank scope", func() error { _, err := NewAuthorizationContext([]string{" "}); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil {
				t.Fatal("expected invalid identity error")
			}
		})
	}
}

func TestAgentAndWorkloadIdentitiesRemainDistinct(t *testing.T) {
	agent, err := NewAgentIdentity("urn:agent:demo", "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	workload, err := NewWorkloadIdentity("spiffe://example.org/agent/demo")
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID == workload.SPIFFEID {
		t.Fatal("logical agent identity must not collapse into workload identity")
	}
}

func TestNewRequestIdentityContextRejectsUnconstructedValues(t *testing.T) {
	_, err := NewRequestIdentityContext(UserIdentity{}, AgentIdentity{}, WorkloadIdentity{}, WorkloadIdentity{}, TransactionIdentity{}, AuthorizationContext{})
	if err == nil {
		t.Fatal("expected incomplete identity context to be rejected")
	}
}
