package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/transaction"
	"example.com/workload-agent-identity/pkg/ttsadapter"
)

var ErrStrictAgent = errors.New("strict agent transaction failed")

type StrictTokenVerifier interface {
	Verify(context.Context, string) (transaction.TxnTokenClaims, error)
}

type StrictRunner struct {
	SPIFFE       corespiffe.Provider
	AdapterHTTP  *http.Client
	GatewayHTTP  *http.Client
	AdapterURL   string
	GatewayURL   string
	Verifier     StrictTokenVerifier
	MaximumBytes int
	WorkloadID   string
	AgentID      string
}

func (r StrictRunner) Run(ctx context.Context, userToken string) error {
	_, err := r.Invoke(ctx, userToken, "system.whoami", "system.whoami")
	return err
}

func (r StrictRunner) Invoke(ctx context.Context, userToken, purpose, tool string) (string, error) {
	if r.SPIFFE == nil || r.AdapterHTTP == nil || r.AdapterHTTP.Timeout <= 0 || r.GatewayHTTP == nil || r.GatewayHTTP.Timeout <= 0 || r.Verifier == nil || r.MaximumBytes <= 0 || userToken == "" || len(userToken) > r.MaximumBytes {
		return "", ErrStrictAgent
	}
	workloadID, agentID := r.WorkloadID, r.AgentID
	if workloadID == "" && agentID == "" {
		workloadID, agentID = "spiffe://example.org/agent/demo", "urn:agent:demo"
	}
	if workloadID == "" || agentID == "" || purpose != "system.whoami" || tool != "system.whoami" {
		return "", ErrStrictAgent
	}
	adapterURL, err := fixedHTTPS(r.AdapterURL)
	if err != nil {
		return "", ErrStrictAgent
	}
	gatewayURL, err := fixedHTTPS(r.GatewayURL)
	if err != nil {
		return "", ErrStrictAgent
	}
	adapterHTTP := *r.AdapterHTTP
	adapterHTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	gatewayHTTP := *r.GatewayHTTP
	gatewayHTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	svid, err := r.SPIFFE.FetchJWTSVID(ctx, []string{"urn:pingfederate:wai:token-exchange"})
	if err != nil || svid.SPIFFEID != workloadID || svid.Token == "" || len(svid.Token) > r.MaximumBytes {
		return "", ErrStrictAgent
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {userToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "actor_token": {svid.Token},
		"actor_token_type": {"urn:ietf:params:oauth:token-type:jwt"}, "requested_token_type": {ttsadapter.TransactionTokenType},
		"audience": {"example.org"}, "scope": {"mcp.system.whoami"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapterURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrStrictAgent
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := adapterHTTP.Do(request)
	if err != nil {
		return "", ErrStrictAgent
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrStrictAgent
	}
	result, err := decodeStrictAdapterResponse(response.Body, r.MaximumBytes)
	if err != nil {
		return "", ErrStrictAgent
	}
	claims, err := r.Verifier.Verify(ctx, result.AccessToken)
	if err != nil || claims.RequestingWorkloadID != workloadID || claims.TransactionContext.WAI.Agent.ID != agentID || claims.TransactionContext.WAI.Target != "demo" || claims.TransactionContext.WAI.Tool != tool || len(claims.Scope) != 1 || claims.Scope[0] != "mcp.system.whoami" || claims.TransactionID == "" {
		return "", ErrStrictAgent
	}
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system.whoami","arguments":{}}}`
	invoke, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL, strings.NewReader(payload))
	if err != nil || transaction.SetTxnToken(invoke.Header, result.AccessToken, r.MaximumBytes) != nil {
		return "", ErrStrictAgent
	}
	invoke.Header.Set("Content-Type", "application/json")
	invoke.Header.Set("Accept", "application/json, text/event-stream")
	invoke.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	invoke.Header.Set("Mcp-Method", "tools/call")
	invoke.Header.Set("Mcp-Name", "system.whoami")
	invocation, err := gatewayHTTP.Do(invoke)
	if err != nil {
		return "", ErrStrictAgent
	}
	defer invocation.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(invocation.Body, int64(r.MaximumBytes)+1))
	if readErr != nil || len(body) > r.MaximumBytes || invocation.StatusCode < 200 || invocation.StatusCode >= 300 {
		return "", ErrStrictAgent
	}
	return claims.TransactionID, nil
}

type strictAdapterResponse struct {
	AccessToken     string
	IssuedTokenType string
	TokenType       string
	ExpiresIn       int64
}

func decodeStrictAdapterResponse(reader io.Reader, maximumBytes int) (strictAdapterResponse, error) {
	body, err := io.ReadAll(io.LimitReader(reader, int64(maximumBytes)+1))
	if err != nil || len(body) > maximumBytes {
		return strictAdapterResponse{}, ErrStrictAgent
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return strictAdapterResponse{}, ErrStrictAgent
	}
	seen := map[string]struct{}{}
	result := strictAdapterResponse{}
	for decoder.More() {
		nameToken, err := decoder.Token()
		name, ok := nameToken.(string)
		if err != nil || !ok {
			return strictAdapterResponse{}, ErrStrictAgent
		}
		if _, exists := seen[name]; exists {
			return strictAdapterResponse{}, ErrStrictAgent
		}
		seen[name] = struct{}{}
		switch name {
		case "access_token":
			err = decoder.Decode(&result.AccessToken)
		case "issued_token_type":
			err = decoder.Decode(&result.IssuedTokenType)
		case "token_type":
			err = decoder.Decode(&result.TokenType)
		case "expires_in":
			err = decoder.Decode(&result.ExpiresIn)
		default:
			return strictAdapterResponse{}, ErrStrictAgent
		}
		if err != nil {
			return strictAdapterResponse{}, ErrStrictAgent
		}
	}
	if _, err := decoder.Token(); err != nil || decoder.Decode(&struct{}{}) != io.EOF || len(seen) != 4 || result.AccessToken == "" || len(result.AccessToken) > maximumBytes || result.IssuedTokenType != ttsadapter.TransactionTokenType || result.TokenType != "N_A" || result.ExpiresIn <= 0 || result.ExpiresIn > 60 {
		return strictAdapterResponse{}, ErrStrictAgent
	}
	return result, nil
}

func fixedHTTPS(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrStrictAgent
	}
	return parsed.String(), nil
}
