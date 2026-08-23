package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
)

const (
	pingAuthorizeResponseLimit = 64 << 10
	pingAuthorizeService       = "WAI MCP"
	pingAuthorizeDomain        = "WAI"
	pingAuthorizeAction        = "Invoke"
)

// PingAuthorize evaluates already-verified identity and route data with the
// PingAuthorize JSON PDP API. It treats every incomplete or ambiguous result
// as a denial.
type PingAuthorize struct {
	client   *http.Client
	endpoint string
	timeout  time.Duration
}

type pingAuthorizeRequest struct {
	Service    string            `json:"service"`
	Domain     string            `json:"domain"`
	Action     string            `json:"action"`
	Attributes map[string]string `json:"attributes"`
}

type pingAuthorizeResponse struct {
	ID                  string                   `json:"id"`
	DeploymentPackageID string                   `json:"deploymentPackageId"`
	Timestamp           string                   `json:"timestamp"`
	ElapsedTime         int64                    `json:"elapsedTime"`
	Decision            string                   `json:"decision"`
	Authorised          *bool                    `json:"authorised"`
	Statements          []pingAuthorizeStatement `json:"statements"`
	Status              pingAuthorizeStatus      `json:"status"`
}

type pingAuthorizeStatement struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Code       string            `json:"code"`
	Payload    string            `json:"payload"`
	Obligatory bool              `json:"obligatory"`
	Fulfilled  bool              `json:"fulfilled"`
	Attributes map[string]string `json:"attributes"`
}

type pingAuthorizeStatus struct {
	Code     string            `json:"code"`
	Messages []json.RawMessage `json:"messages"`
	Errors   []json.RawMessage `json:"errors"`
}

func NewPingAuthorize(client *http.Client, endpoint string, timeout time.Duration) (*PingAuthorize, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/governance-engine" {
		return nil, errors.New("PingAuthorize HTTPS governance endpoint is required")
	}
	if client == nil || client.Timeout <= 0 || timeout <= 0 {
		return nil, errors.New("PingAuthorize bounded HTTP client and decision timeout are required")
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("PingAuthorize TLS verification must not be disabled")
	}
	return &PingAuthorize{client: client, endpoint: parsed.String(), timeout: timeout}, nil
}

func (p *PingAuthorize) Authorize(ctx context.Context, value identity.RequestIdentityContext, target, tool string) error {
	if p == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(target) == "" || strings.TrimSpace(target) != target || strings.TrimSpace(tool) == "" || strings.TrimSpace(tool) != tool ||
		value.User.ID == "" || value.Agent.ID == "" || value.Agent.InstanceID == "" || value.OriginalWorkload.SPIFFEID == "" || value.ImmediateCaller.SPIFFEID == "" || value.Transaction.ID == "" || value.Transaction.Purpose == "" {
		return ErrDenied
	}
	scopes, ok := canonicalScopes(value.Authorization.Scope)
	if !ok {
		return ErrDenied
	}
	body, err := json.Marshal(pingAuthorizeRequest{
		Service: pingAuthorizeService, Domain: pingAuthorizeDomain, Action: pingAuthorizeAction,
		Attributes: map[string]string{
			"user_id": value.User.ID, "agent_id": value.Agent.ID,
			"agent_instance_id": value.Agent.InstanceID, "workload_id": value.OriginalWorkload.SPIFFEID,
			"immediate_caller_id": value.ImmediateCaller.SPIFFEID, "transaction_id": value.Transaction.ID,
			"purpose": value.Transaction.Purpose, "scope": strings.Join(scopes, " "),
			"target": target, "tool": tool,
		},
	})
	if err != nil {
		return ErrDenied
	}
	decisionCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(decisionCtx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return ErrDenied
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return ErrDenied
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, pingAuthorizeResponseLimit+1))
	decoder.DisallowUnknownFields()
	var result pingAuthorizeResponse
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrDenied
	}
	if result.ID == "" || result.DeploymentPackageID == "" || result.Timestamp == "" || result.Status.Code != "OKAY" || len(result.Status.Errors) != 0 || result.Authorised == nil || !*result.Authorised || result.Decision != "PERMIT" {
		return ErrDenied
	}
	for _, statement := range result.Statements {
		if statement.Obligatory && !statement.Fulfilled {
			return ErrDenied
		}
	}
	return nil
}

func canonicalScopes(scopes []string) ([]string, bool) {
	if len(scopes) == 0 {
		return nil, false
	}
	result := append([]string(nil), scopes...)
	sort.Strings(result)
	for i, scope := range result {
		if scope == "" || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") || (i > 0 && scope == result[i-1]) {
			return nil, false
		}
	}
	return result, true
}
