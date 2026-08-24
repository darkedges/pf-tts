package pingfederate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	AccessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	JWTTokenType           = "urn:ietf:params:oauth:token-type:jwt"
)

type ExchangeRequest struct {
	SubjectToken       string
	ActorToken         string
	SubjectTokenType   string
	ActorTokenType     string
	Audience           string
	Scope              []string
	TransactionID      string
	TransactionPurpose string
	AgentInstanceID    string
}

type ExchangeResponse struct {
	AccessToken     string
	TokenType       string
	IssuedTokenType string
	ExpiresIn       int64
	Scope           string
}

type TokenExchanger interface {
	Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error)
}

var (
	ErrInvalidExchange = errors.New("invalid token exchange request")
	ErrExchangeFailed  = errors.New("token exchange failed")
)

type Client struct {
	endpoint     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

func NewClient(endpoint, clientID, clientSecret string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("%w: token endpoint must be an HTTPS URL without query parameters", ErrInvalidExchange)
	}
	if strings.TrimSpace(clientID) == "" || clientSecret == "" {
		return nil, fmt.Errorf("%w: OAuth client credentials are required", ErrInvalidExchange)
	}
	if httpClient == nil || httpClient.Timeout <= 0 {
		return nil, fmt.Errorf("%w: HTTP client with explicit timeout is required", ErrInvalidExchange)
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: parsed.String(), clientID: clientID, clientSecret: clientSecret, httpClient: &client}, nil
}

func (c *Client) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error) {
	if err := validateExchangeRequest(request); err != nil {
		return ExchangeResponse{}, err
	}
	form := url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {request.SubjectToken},
		"subject_token_type": {request.SubjectTokenType}, "actor_token": {request.ActorToken},
		"actor_token_type": {request.ActorTokenType}, "requested_token_type": {AccessTokenType},
		"audience": {request.Audience},
	}
	if len(request.Scope) > 0 {
		form.Set("scope", strings.Join(request.Scope, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("%w: create request", ErrExchangeFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)
	response, err := c.httpClient.Do(req)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("%w: endpoint request failed", ErrExchangeFailed)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return ExchangeResponse{}, fmt.Errorf("%w: read response", ErrExchangeFailed)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var oauth struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauth)
		code := strings.TrimSpace(oauth.Error)
		if code == "" {
			code = "http_error"
		}
		return ExchangeResponse{}, fmt.Errorf("%w: status=%d code=%s", ErrExchangeFailed, response.StatusCode, code)
	}
	var result struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int64  `json:"expires_in"`
		Scope           string `json:"scope"`
	}
	fields, err := uniqueJSONObjectFields(body)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("%w: invalid success response", ErrExchangeFailed)
	}
	allowed := map[string]struct{}{"access_token": {}, "issued_token_type": {}, "token_type": {}, "expires_in": {}, "scope": {}}
	for name := range fields {
		if _, ok := allowed[name]; !ok {
			return ExchangeResponse{}, fmt.Errorf("%w: invalid success response", ErrExchangeFailed)
		}
	}
	if err := json.Unmarshal(body, &result); err != nil || result.AccessToken == "" || result.TokenType == "" {
		return ExchangeResponse{}, fmt.Errorf("%w: invalid success response", ErrExchangeFailed)
	}
	return ExchangeResponse{AccessToken: result.AccessToken, IssuedTokenType: result.IssuedTokenType, TokenType: result.TokenType, ExpiresIn: result.ExpiresIn, Scope: result.Scope}, nil
}

func uniqueJSONObjectFields(body []byte) (map[string]struct{}, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("response is not an object")
	}
	fields := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("invalid object key")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate object key")
		}
		fields[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	return fields, nil
}

func validateExchangeRequest(r ExchangeRequest) error {
	if strings.TrimSpace(r.SubjectToken) == "" || strings.TrimSpace(r.ActorToken) == "" || strings.TrimSpace(r.SubjectTokenType) == "" || strings.TrimSpace(r.ActorTokenType) == "" || strings.TrimSpace(r.Audience) == "" {
		return fmt.Errorf("%w: tokens, token types, and audience are required", ErrInvalidExchange)
	}
	for _, scope := range r.Scope {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("%w: scope cannot be empty", ErrInvalidExchange)
		}
	}
	return nil
}

func NewDefaultHTTPClient(timeout time.Duration) *http.Client { return &http.Client{Timeout: timeout} }
