package authorization

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"example.com/workload-agent-identity/pkg/identity"
)

const opaDecision = "data.wai.authz.allow"

type OPA struct {
	query   rego.PreparedEvalQuery
	timeout time.Duration
}

type opaInput struct {
	AgentID         string   `json:"agent_id"`
	AgentInstanceID string   `json:"agent_instance_id"`
	WorkloadID      string   `json:"workload_id"`
	Purpose         string   `json:"purpose"`
	Scopes          []string `json:"scopes"`
	Target          string   `json:"target"`
	Tool            string   `json:"tool"`
}

func NewOPA(ctx context.Context, policyPath string, timeout time.Duration) (*OPA, error) {
	if ctx == nil || strings.TrimSpace(policyPath) == "" || timeout <= 0 {
		return nil, errors.New("OPA policy path, context, and positive timeout are required")
	}
	file, err := os.Open(policyPath)
	if err != nil {
		return nil, fmt.Errorf("open OPA authorization policy: %w", err)
	}
	module, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, errors.New("read OPA authorization policy")
	}
	if len(module) == 0 || len(module) > 1<<20 {
		return nil, errors.New("OPA authorization policy must be between 1 byte and 1 MiB")
	}
	capabilities := ast.CapabilitiesForThisVersion()
	allowed := capabilities.Builtins[:0]
	for _, builtin := range capabilities.Builtins {
		if builtin.Name != "http.send" && builtin.Name != "net.lookup_ip_addr" {
			allowed = append(allowed, builtin)
		}
	}
	capabilities.Builtins = allowed
	prepared, err := rego.New(
		rego.Query(opaDecision),
		rego.Module(filepath.Base(policyPath), string(module)),
		rego.Capabilities(capabilities),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile OPA authorization policy: %w", err)
	}
	return &OPA{query: prepared, timeout: timeout}, nil
}

func (o *OPA) Authorize(ctx context.Context, value identity.RequestIdentityContext, target, tool string) error {
	if o == nil || ctx == nil {
		return ErrDenied
	}
	if ctx.Err() != nil {
		return ErrDenied
	}
	evalCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	results, err := o.query.Eval(evalCtx, rego.EvalInput(opaInput{
		AgentID: value.Agent.ID, AgentInstanceID: value.Agent.InstanceID,
		WorkloadID: value.OriginalWorkload.SPIFFEID, Purpose: value.Transaction.Purpose,
		Scopes: append([]string(nil), value.Authorization.Scope...), Target: target, Tool: tool,
	}))
	if err != nil || evalCtx.Err() != nil || len(results) != 1 || len(results[0].Expressions) != 1 {
		return ErrDenied
	}
	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok || !allowed {
		return ErrDenied
	}
	return nil
}
