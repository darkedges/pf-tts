package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"example.com/workload-agent-identity/pkg/identity"
)

var ErrDenied = errors.New("authorization denied")

type Rule struct {
	AgentID    string   `json:"agent_id"`
	WorkloadID string   `json:"workload_id"`
	Purposes   []string `json:"purposes"`
	Scopes     []string `json:"scopes"`
	Target     string   `json:"target"`
	Tools      []string `json:"tools"`
}

type document struct {
	Rules []Rule `json:"rules"`
}

type key struct{ agent, workload, purpose, target, tool string }

type Policy struct{ requiredScopes map[key]map[string]struct{} }

func LoadJSON(reader io.Reader) (*Policy, error) {
	if reader == nil {
		return nil, errors.New("authorization policy reader is required")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	var config document
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid authorization policy: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid authorization policy: trailing JSON value")
	}
	if len(config.Rules) == 0 {
		return nil, errors.New("authorization policy has no rules")
	}
	policy := &Policy{requiredScopes: make(map[key]map[string]struct{})}
	for _, rule := range config.Rules {
		if err := policy.add(rule); err != nil {
			return nil, err
		}
	}
	return policy, nil
}

func (p *Policy) add(rule Rule) error {
	rule.AgentID = strings.TrimSpace(rule.AgentID)
	rule.WorkloadID = strings.TrimSpace(rule.WorkloadID)
	rule.Target = strings.TrimSpace(rule.Target)
	if rule.AgentID == "" || !strings.HasPrefix(rule.WorkloadID, "spiffe://") || rule.Target == "" || len(rule.Purposes) == 0 || len(rule.Scopes) == 0 || len(rule.Tools) == 0 {
		return errors.New("authorization rule is missing a required trusted binding")
	}
	scopes := make(map[string]struct{}, len(rule.Scopes))
	for _, raw := range rule.Scopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return errors.New("authorization rule contains an empty scope")
		}
		scopes[scope] = struct{}{}
	}
	for _, rawPurpose := range rule.Purposes {
		purpose := strings.TrimSpace(rawPurpose)
		for _, rawTool := range rule.Tools {
			tool := strings.TrimSpace(rawTool)
			if purpose == "" || tool == "" {
				return errors.New("authorization rule contains an empty purpose or tool")
			}
			binding := key{rule.AgentID, rule.WorkloadID, purpose, rule.Target, tool}
			if _, exists := p.requiredScopes[binding]; exists {
				return errors.New("authorization policy contains an ambiguous duplicate binding")
			}
			p.requiredScopes[binding] = scopes
		}
	}
	return nil
}

func (p *Policy) Authorize(_ context.Context, value identity.RequestIdentityContext, target, tool string) error {
	if p == nil {
		return ErrDenied
	}
	required, ok := p.requiredScopes[key{value.Agent.ID, value.OriginalWorkload.SPIFFEID, value.Transaction.Purpose, target, tool}]
	if !ok {
		return ErrDenied
	}
	granted := make(map[string]struct{}, len(value.Authorization.Scope))
	for _, scope := range value.Authorization.Scope {
		granted[scope] = struct{}{}
	}
	for scope := range required {
		if _, ok := granted[scope]; !ok {
			return ErrDenied
		}
	}
	return nil
}
