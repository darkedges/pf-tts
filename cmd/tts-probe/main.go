package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/transaction"
	"example.com/workload-agent-identity/pkg/ttsadapter"
	"github.com/go-jose/go-jose/v4"
)

const (
	actorAudience = "urn:pingfederate:wai:token-exchange"
	trustDomain   = "example.org"
	strictScope   = "mcp.system.whoami"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	expectedID, err := demoenv.Required("PROBE_SPIFFE_ID")
	if err != nil {
		return err
	}
	expectRejection := strings.EqualFold(strings.TrimSpace(os.Getenv("EXPECT_REJECTION")), "true")
	provider, source, err := demoenv.Provider(ctx, expectedID)
	if err != nil {
		return err
	}
	defer provider.Close()
	strictGateway := strings.TrimSpace(os.Getenv("STRICT_MCP_GATEWAY_URL"))
	if strings.EqualFold(strings.TrimSpace(os.Getenv("EXPECT_STRICT_TLS_REJECTION")), "true") {
		return expectStrictTLSRejection(ctx, source, strictGateway)
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("EXPECT_STRICT_BEARER_REJECTION")), "true") {
		return expectStrictBearerRejection(ctx, source, strictGateway)
	}
	peer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/tts/adapter")
	if err != nil {
		return err
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		return err
	}
	endpoint, err := demoenv.Required("TTS_ADAPTER_URL")
	if err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("TTS_ADAPTER_URL must be a fixed HTTPS URL")
	}
	if expectRejection {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("rejected-before-token-processing=true"))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := client.Do(req)
		if err == nil {
			defer response.Body.Close()
			return fmt.Errorf("wrong SPIFFE workload unexpectedly reached adapter: status=%d", response.StatusCode)
		}
		fmt.Println("PASS: wrong SPIFFE workload rejected during adapter mTLS authentication.")
		return nil
	}
	svid, err := provider.FetchJWTSVID(ctx, []string{actorAudience})
	if err != nil {
		return err
	}
	subject, err := obtainSubjectToken(ctx)
	if err != nil {
		return err
	}
	form := url.Values{
		"grant_type": {pingfederate.TokenExchangeGrantType}, "subject_token": {subject},
		"subject_token_type": {pingfederate.AccessTokenType}, "actor_token": {svid.Token},
		"actor_token_type": {pingfederate.JWTTokenType}, "requested_token_type": {ttsadapter.TransactionTokenType},
		"audience": {trustDomain}, "scope": {strictScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("adapter request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(body) > 32<<10 {
		return fmt.Errorf("adapter returned an invalid bounded response: status=%d", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		code := "invalid_error_response"
		if json.Unmarshal(body, &failure) == nil {
			switch failure.Error {
			case "invalid_request", "invalid_client", "temporarily_unavailable", "server_error":
				code = failure.Error
			}
		}
		return fmt.Errorf("adapter rejected request: status=%d code=%s", response.StatusCode, code)
	}
	var result struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.AccessToken == "" || result.IssuedTokenType != ttsadapter.TransactionTokenType || result.TokenType != "N_A" || result.ExpiresIn != 20 {
		return fmt.Errorf("adapter outer Transaction Token response was invalid")
	}
	verifier, err := strictVerifier()
	if err != nil {
		return err
	}
	claims, err := verifier.Verify(ctx, result.AccessToken)
	if err != nil || claims.RequestingWorkloadID != expectedID || claims.Audience != trustDomain || claims.TransactionContext.WAI.Target != "demo" || claims.TransactionContext.WAI.Tool != "system.whoami" {
		return fmt.Errorf("adapter returned an invalid strict inner Transaction Token")
	}
	if strictGateway != "" {
		if err := invokeStrictGateway(ctx, source, strictGateway, result.AccessToken); err != nil {
			return err
		}
	}
	fmt.Println("PASS: approved SPIFFE requester received exact outer semantics and a verified unchanged strict inner Transaction Token.")
	return nil
}

func strictGatewayClient(ctx context.Context, source corespiffe.X509Source, endpoint string) (*http.Client, string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", fmt.Errorf("strict gateway URL is invalid")
	}
	peer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp-strict")
	if err != nil {
		return nil, "", fmt.Errorf("strict gateway peer policy failed")
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("strict gateway client failed")
	}
	return client, parsed.String(), nil
}

func expectStrictTLSRejection(ctx context.Context, source corespiffe.X509Source, endpoint string) error {
	client, endpoint, err := strictGatewayClient(ctx, source, endpoint)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("strict TLS rejection request creation failed")
	}
	response, err := client.Do(request)
	if err == nil {
		response.Body.Close()
		return fmt.Errorf("wrong SPIFFE workload unexpectedly reached strict gateway: status=%d", response.StatusCode)
	}
	fmt.Println("PASS: wrong SPIFFE workload rejected during strict gateway mTLS authentication.")
	return nil
}

func expectStrictBearerRejection(ctx context.Context, source corespiffe.X509Source, endpoint string) error {
	client, endpoint, err := strictGatewayClient(ctx, source, endpoint)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("strict Bearer rejection request creation failed")
	}
	request.Header.Set("Authorization", "Bearer invalid-probe-value")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("strict Bearer rejection request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<10)+1))
	if err != nil || len(body) > 4<<10 {
		return fmt.Errorf("strict Bearer rejection response was not bounded")
	}
	if response.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("strict gateway did not reject legacy Bearer transport: status=%d", response.StatusCode)
	}
	fmt.Println("PASS: strict gateway rejected legacy Bearer transport.")
	return nil
}

func invokeStrictGateway(ctx context.Context, source corespiffe.X509Source, endpoint, rawToken string) error {
	client, endpoint, err := strictGatewayClient(ctx, source, endpoint)
	if err != nil {
		return err
	}
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system.whoami","arguments":{}}}`
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil || transaction.SetTxnToken(request.Header, rawToken, 16<<10) != nil {
		return fmt.Errorf("strict gateway request creation failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "system.whoami")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("strict gateway request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(body) > 32<<10 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("strict gateway rejected verified Transaction Token: status=%d", response.StatusCode)
	}
	fmt.Println("PASS: strict gateway, MCP server, and API accepted one unchanged Transaction Token.")
	return nil
}

func obtainSubjectToken(ctx context.Context) (string, error) {
	endpoint, err := demoenv.Required("PF_TOKEN_ENDPOINT")
	if err != nil {
		return "", err
	}
	client, err := demoenv.PFHTTPClient()
	if err != nil {
		return "", err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	username := strings.TrimSpace(os.Getenv("TF_VAR_lab_user_name"))
	if username == "" {
		username = "demo-user"
	}
	clientID := strings.TrimSpace(os.Getenv("TF_VAR_lab_user_client_id"))
	if clientID == "" {
		clientID = "wai-lab-user"
	}
	password := os.Getenv("TF_VAR_lab_user_password")
	clientSecret := os.Getenv("TF_VAR_lab_user_client_secret")
	if password == "" || clientSecret == "" {
		return "", fmt.Errorf("subject token credentials are required")
	}
	form := url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}, "scope": {strictScope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("subject token endpoint failed")
	}
	defer response.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || result.AccessToken == "" {
		return "", fmt.Errorf("subject token request was rejected")
	}
	return result.AccessToken, nil
}

func strictVerifier() (*transaction.TxnTokenVerifier, error) {
	issuer, err := demoenv.Required("PF_TRANSACTION_ISSUER")
	if err != nil {
		return nil, err
	}
	jwks, err := demoenv.Required("PF_JWKS_URL")
	if err != nil {
		return nil, err
	}
	client, err := demoenv.PFHTTPClient()
	if err != nil {
		return nil, err
	}
	keys, err := pingfederate.NewJWKSKeyResolver(jwks, client, 1<<20)
	if err != nil {
		return nil, err
	}
	return transaction.NewTxnTokenVerifier(transaction.TxnTokenVerifierConfig{
		Mode: transaction.ProfileTxnTokenV11, Issuer: issuer, TrustDomain: trustDomain,
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: 5 * time.Second,
		MaximumLifetime: 60 * time.Second, MaximumTokenBytes: 16 << 10, MaximumPayloadBytes: 8 << 10,
		MaximumIdentifierBytes: 256, MaximumContextBytes: 2 << 10, MaximumScopes: 1,
		AllowedScopes:         map[string]struct{}{strictScope: {}},
		WorkloadAgentBindings: map[string]string{"spiffe://example.org/agent/demo": "urn:agent:demo"}, Keys: keys,
	})
}
