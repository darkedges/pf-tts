package identity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	ErrInvalidBinding  = errors.New("invalid agent binding")
	ErrUnknownWorkload = errors.New("unknown workload identity")
)

type AgentBinding struct {
	SPIFFEID string
	AgentID  string
}

type AgentRegistry struct {
	byWorkload map[string]AgentIdentity
}

func NewAgentRegistry(bindings []AgentBinding) (*AgentRegistry, error) {
	if len(bindings) == 0 {
		return nil, fmt.Errorf("%w: at least one binding is required", ErrInvalidBinding)
	}
	registry := &AgentRegistry{byWorkload: make(map[string]AgentIdentity, len(bindings))}
	for _, binding := range bindings {
		workloadID, err := spiffeid.FromString(strings.TrimSpace(binding.SPIFFEID))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid SPIFFE ID", ErrInvalidBinding)
		}
		agent, err := NewLogicalAgentIdentity(binding.AgentID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid logical Agent ID", ErrInvalidBinding)
		}
		key := workloadID.String()
		if existing, ok := registry.byWorkload[key]; ok {
			return nil, fmt.Errorf("%w: SPIFFE ID has conflicting bindings for %q and %q", ErrInvalidBinding, existing.ID, agent.ID)
		}
		registry.byWorkload[key] = agent
	}
	return registry, nil
}

func (r *AgentRegistry) ResolveAgent(rawSPIFFEID string) (AgentIdentity, error) {
	workloadID, err := spiffeid.FromString(strings.TrimSpace(rawSPIFFEID))
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("%w: malformed SPIFFE ID", ErrUnknownWorkload)
	}
	agent, ok := r.byWorkload[workloadID.String()]
	if !ok {
		return AgentIdentity{}, fmt.Errorf("%w: no trusted agent binding", ErrUnknownWorkload)
	}
	return agent, nil
}
