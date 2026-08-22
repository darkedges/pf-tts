package identity

import (
	"errors"
	"testing"
)

func TestAgentRegistryResolveAgent(t *testing.T) {
	registry, err := NewAgentRegistry([]AgentBinding{{SPIFFEID: "spiffe://example.org/agent/demo", AgentID: "urn:agent:demo"}})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := registry.ResolveAgent("spiffe://example.org/agent/demo")
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "urn:agent:demo" || agent.InstanceID != "" {
		t.Fatalf("unexpected resolved agent: %#v", agent)
	}
}

func TestAgentRegistryRejectsUnknownWorkload(t *testing.T) {
	registry, err := NewAgentRegistry([]AgentBinding{{SPIFFEID: "spiffe://example.org/agent/demo", AgentID: "urn:agent:demo"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, workload := range []string{"spiffe://example.org/agent/unknown", "caller-asserted-workload"} {
		if _, err := registry.ResolveAgent(workload); !errors.Is(err, ErrUnknownWorkload) {
			t.Fatalf("expected unknown workload error, got %v", err)
		}
	}
}

func TestAgentRegistryRejectsConflictingMapping(t *testing.T) {
	_, err := NewAgentRegistry([]AgentBinding{
		{SPIFFEID: "spiffe://example.org/agent/demo", AgentID: "urn:agent:demo"},
		{SPIFFEID: "spiffe://example.org/agent/demo", AgentID: "urn:agent:forged"},
	})
	if !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("expected conflicting binding error, got %v", err)
	}
}

func TestCallerSuppliedAgentIDCannotOverrideResolution(t *testing.T) {
	registry, err := NewAgentRegistry([]AgentBinding{{SPIFFEID: "spiffe://example.org/agent/demo", AgentID: "urn:agent:trusted"}})
	if err != nil {
		t.Fatal(err)
	}
	callerSuppliedAgentID := "urn:agent:forged"
	agent, err := registry.ResolveAgent("spiffe://example.org/agent/demo")
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID == callerSuppliedAgentID || agent.ID != "urn:agent:trusted" {
		t.Fatal("caller-supplied Agent ID influenced trusted resolution")
	}
}
