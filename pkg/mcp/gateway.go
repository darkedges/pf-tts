package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/identity"
)

var ErrRouteDenied = errors.New("MCP route denied")

type Target struct {
	Name  string
	URL   *url.URL
	Tools map[string]struct{}
}
type Gateway struct {
	client  *http.Client
	targets map[string]Target
	byTool  map[string]Target
	sole    *Target
	authz   Authorizer
	audit   audit.Sink
}

type Authorizer interface {
	Authorize(context.Context, identity.RequestIdentityContext, string, string) error
}

func NewGateway(client *http.Client, targets []Target) (*Gateway, error) {
	return newGateway(client, targets, nil)
}

func NewGatewayWithAuthorizer(client *http.Client, targets []Target, authorizer Authorizer, sink audit.Sink) (*Gateway, error) {
	if authorizer == nil || sink == nil {
		return nil, errors.New("MCP authorizer and audit sink are required")
	}
	gateway, err := newGateway(client, targets, authorizer)
	if err == nil {
		gateway.audit = sink
	}
	return gateway, err
}

func newGateway(client *http.Client, targets []Target, authorizer Authorizer) (*Gateway, error) {
	if client == nil || client.Timeout <= 0 || len(targets) == 0 {
		return nil, fmt.Errorf("invalid MCP gateway configuration")
	}
	g := &Gateway{client: client, targets: map[string]Target{}, byTool: map[string]Target{}, authz: authorizer}
	for _, target := range targets {
		if target.Name == "" || target.URL == nil || target.URL.Scheme != "https" || target.URL.Host == "" || target.URL.RawQuery != "" || len(target.Tools) == 0 {
			return nil, fmt.Errorf("invalid MCP target")
		}
		if _, ok := g.targets[target.Name]; ok {
			return nil, fmt.Errorf("duplicate MCP target")
		}
		g.targets[target.Name] = target
		for tool := range target.Tools {
			if tool == "" {
				return nil, fmt.Errorf("empty MCP tool")
			}
			if _, ok := g.byTool[tool]; ok {
				return nil, fmt.Errorf("ambiguous MCP tool route")
			}
			g.byTool[tool] = target
		}
	}
	if len(targets) == 1 {
		copy := targets[0]
		g.sole = &copy
	}
	return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	method := r.Header.Get("Mcp-Method")
	name := r.Header.Get("Mcp-Name")
	var target Target
	var ok bool
	if method == "tools/call" {
		target, ok = g.byTool[name]
	} else if g.sole != nil {
		target = *g.sole
		ok = true
	}
	if !ok {
		http.Error(w, "route denied", http.StatusForbidden)
		return
	}
	if g.authz != nil {
		value, verified := identity.FromContext(r.Context())
		if !verified {
			_ = g.audit.Write(audit.Event{Type: audit.MCPToolDenied, Target: target.Name, Decision: "deny", ReasonCode: "verified_identity_missing"})
			http.Error(w, "authorization denied", http.StatusForbidden)
			return
		}
		event := audit.Event{
			TransactionID: value.Transaction.ID, UserID: value.User.ID, AgentID: value.Agent.ID,
			TransactionWorkloadID: value.OriginalWorkload.SPIFFEID, ImmediateCallerSPIFFEID: value.ImmediateCaller.SPIFFEID,
			Target: target.Name + ":" + name, ProtocolMethod: method, Tool: name, Purpose: value.Transaction.Purpose,
		}
		if g.authz.Authorize(r.Context(), value, target.Name, name) != nil {
			event.Type, event.Decision, event.ReasonCode = audit.MCPToolDenied, "deny", "policy_denied"
			_ = g.audit.Write(event)
			http.Error(w, "authorization denied", http.StatusForbidden)
			return
		}
		event.Type, event.Decision, event.ReasonCode = audit.MCPToolAllowed, "allow", "policy_allowed"
		if g.audit.Write(event) != nil {
			http.Error(w, "audit unavailable", http.StatusInternalServerError)
			return
		}
	}
	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "gateway failure", http.StatusBadGateway)
		return
	}
	copyHeaders(out.Header, r.Header)
	response, err := g.client.Do(out)
	if err != nil {
		http.Error(w, "gateway failure", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyHeaders(w.Header(), response.Header)
	w.Header().Set("X-WAI-Response-Source", "downstream")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 8<<20))
}
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
