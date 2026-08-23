package webapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
)

type fakeVerifier struct {
	expectedNonce string
	fail          bool
}

type fakeInvoker struct {
	userToken, purpose, tool string
	err                      error
}

type fakeAuditReader struct{ user string }

func (r *fakeAuditReader) ListByUser(_ context.Context, user string) ([]audit.Record, error) {
	r.user = user
	return []audit.Record{{ID: "record-a", UserID: user, TransactionID: "tx", EventType: audit.MCPToolAllowed}}, nil
}

func (r *fakeAuditReader) GetByUser(_ context.Context, user, id string) (audit.Record, error) {
	r.user = user
	if id != "record-a" {
		return audit.Record{}, audit.ErrRecordMissing
	}
	return audit.Record{ID: id, UserID: user, TransactionID: "tx", EventType: audit.MCPToolAllowed}, nil
}

func (i *fakeInvoker) Invoke(_ context.Context, userToken, purpose, tool string) (string, error) {
	i.userToken, i.purpose, i.tool = userToken, purpose, tool
	if i.err != nil {
		return "", i.err
	}
	return "verified-transaction", nil
}

func (v *fakeVerifier) VerifyIDToken(_ context.Context, token, clientID, nonce string) (string, error) {
	if v.fail || token != "signed-id-token" || clientID != "web-client" || nonce != v.expectedNonce {
		return "", context.Canceled
	}
	return "user-123", nil
}

type flowFixture struct {
	handler  *Handler
	verifier *fakeVerifier
	tokenURL *httptest.Server
	state    string
	cookie   *http.Cookie
}

func newFlow(t *testing.T) *flowFixture {
	return newFlowWithInteractions(t, nil)
}

func newFlowWithInteractions(t *testing.T, invoker InteractionInvoker) *flowFixture {
	return newFlowWithServices(t, invoker, nil)
}

func newFlowWithServices(t *testing.T, invoker InteractionInvoker, auditReader AuditReader) *flowFixture {
	t.Helper()
	verifier := &fakeVerifier{}
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") == "" {
			t.Error("token request did not use authenticated POST")
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != "https://app.example/oauth/callback" {
			t.Errorf("invalid token form: %#v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "subject-access-token", IDToken: "signed-id-token", TokenType: "Bearer"})
	}))
	t.Cleanup(tokenServer.Close)
	tokenServer.Client().Timeout = time.Second
	var allowed []AllowedInteraction
	if invoker != nil {
		allowed = []AllowedInteraction{{Tool: "system.whoami", Purpose: "system.whoami"}}
	}
	handler, err := New(Config{AuthorizationEndpoint: tokenServer.URL + "/authorize", TokenEndpoint: tokenServer.URL + "/token", RedirectURI: "https://app.example/oauth/callback", PublicOrigin: "https://app.example", ClientID: "web-client", ClientSecret: "secret", Scopes: []string{"openid"}, CookieName: "__Host-wai_session", SessionTTL: time.Hour, PreAuthTTL: time.Minute, MaximumSessions: 10, HTTPClient: tokenServer.Client(), Verifier: verifier, Interactions: invoker, AllowedInteractions: allowed, Audit: auditReader})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://app.example/login", nil))
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil || location.Query().Get("state") == "" || location.Query().Get("nonce") == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid authorization redirect: %s", login.Header().Get("Location"))
	}
	verifier.expectedNonce = location.Query().Get("nonce")
	return &flowFixture{handler: handler, verifier: verifier, tokenURL: tokenServer, state: location.Query().Get("state")}
}

func authenticatedInteractionRequest(t *testing.T, flow *flowFixture, body string) (*http.Cookie, string, *http.Request) {
	t.Helper()
	callback := flow.callback(t, flow.state, nil)
	cookie := callback.Result().Cookies()[0]
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://app.example/api/session", nil)
	sessionRequest.AddCookie(cookie)
	sessionResponse := httptest.NewRecorder()
	flow.handler.ServeHTTP(sessionResponse, sessionRequest)
	var sessionBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(sessionResponse.Body.Bytes(), &sessionBody); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.example/api/interactions", strings.NewReader(body))
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("X-CSRF-Token", sessionBody.CSRF)
	request.Header.Set("Content-Type", "application/json")
	return cookie, sessionBody.CSRF, request
}

func (f *flowFixture) callback(t *testing.T, state string, existing *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://app.example/oauth/callback?code=authorization-code&state="+url.QueryEscape(state), nil)
	if existing != nil {
		request.AddCookie(existing)
	}
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestAuthorizationFlowUsesPKCEAndOpaqueSecureSession(t *testing.T) {
	flow := newFlow(t)
	attackerCookie := &http.Cookie{Name: "__Host-wai_session", Value: "attacker-fixed"}
	callback := flow.callback(t, flow.state, attackerCookie)
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, body = %s", callback.Code, callback.Body.String())
	}
	cookies := callback.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == attackerCookie.Value || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" {
		t.Fatalf("unsafe or fixed session cookie: %#v", cookies)
	}
	if strings.Contains(callback.Body.String()+callback.Header().Get("Location")+cookies[0].String(), "subject-access-token") || strings.Contains(cookies[0].String(), "user-123") {
		t.Fatal("credential or identity leaked to browser response")
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://app.example/api/session", nil)
	sessionRequest.AddCookie(cookies[0])
	sessionResponse := httptest.NewRecorder()
	flow.handler.ServeHTTP(sessionResponse, sessionRequest)
	if sessionResponse.Code != http.StatusOK || !strings.Contains(sessionResponse.Body.String(), "user-123") || strings.Contains(sessionResponse.Body.String(), "subject-access-token") {
		t.Fatalf("unsafe session response: %d %s", sessionResponse.Code, sessionResponse.Body.String())
	}
}

func TestCallbackStateIsSingleUseAndExact(t *testing.T) {
	flow := newFlow(t)
	if response := flow.callback(t, "forged", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("forged state status = %d", response.Code)
	}
	if response := flow.callback(t, flow.state, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("first callback status = %d", response.Code)
	}
	if response := flow.callback(t, flow.state, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed state status = %d", response.Code)
	}
}

func TestPreAuthenticationStateExpiresAndCapacityFailsClosed(t *testing.T) {
	flow := newFlow(t)
	flow.handler.config.MaximumSessions = 1
	full := httptest.NewRecorder()
	flow.handler.ServeHTTP(full, httptest.NewRequest(http.MethodGet, "https://app.example/login", nil))
	if full.Code != http.StatusInternalServerError {
		t.Fatalf("capacity exhaustion status = %d", full.Code)
	}
	flow.handler.config.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if response := flow.callback(t, flow.state, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("expired state status = %d", response.Code)
	}
}

func TestFailedIDTokenVerificationDoesNotCreateSession(t *testing.T) {
	flow := newFlow(t)
	flow.verifier.fail = true
	response := flow.callback(t, flow.state, nil)
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 {
		t.Fatalf("failed verification created a session: %d %#v", response.Code, response.Result().Cookies())
	}
}

func TestLogoutRequiresOriginAndCSRF(t *testing.T) {
	flow := newFlow(t)
	callback := flow.callback(t, flow.state, nil)
	cookie := callback.Result().Cookies()[0]
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://app.example/api/session", nil)
	sessionRequest.AddCookie(cookie)
	sessionResponse := httptest.NewRecorder()
	flow.handler.ServeHTTP(sessionResponse, sessionRequest)
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(sessionResponse.Body.Bytes(), &body)

	for _, tc := range []struct{ origin, csrf string }{{"https://attacker.example", body.CSRF}, {"https://app.example", "forged"}} {
		request := httptest.NewRequest(http.MethodPost, "https://app.example/logout", nil)
		request.AddCookie(cookie)
		request.Header.Set("Origin", tc.origin)
		request.Header.Set("X-CSRF-Token", tc.csrf)
		response := httptest.NewRecorder()
		flow.handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid CSRF accepted: %d", response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.example/logout", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("X-CSRF-Token", body.CSRF)
	response := httptest.NewRecorder()
	flow.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("valid logout failed: %d", response.Code)
	}
}

func TestInteractionUsesOnlyServerSessionAndAllowlistedPair(t *testing.T) {
	invoker := &fakeInvoker{}
	flow := newFlowWithInteractions(t, invoker)
	_, _, request := authenticatedInteractionRequest(t, flow, `{"tool":"system.whoami","purpose":"system.whoami"}`)
	response := httptest.NewRecorder()
	flow.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || invoker.userToken != "subject-access-token" || invoker.tool != "system.whoami" || invoker.purpose != "system.whoami" {
		t.Fatalf("trusted invocation failed: status=%d token=%q pair=%s/%s", response.Code, invoker.userToken, invoker.tool, invoker.purpose)
	}
	if strings.Contains(response.Body.String(), "subject-access-token") {
		t.Fatal("subject token leaked in interaction response")
	}
}

func TestInteractionRejectsBrowserIdentityAndRoutingOverrides(t *testing.T) {
	for _, body := range []string{
		`{"tool":"system.whoami","purpose":"system.whoami","agent_id":"urn:agent:forged"}`,
		`{"tool":"system.whoami","purpose":"system.whoami","workload_id":"spiffe://attacker/workload"}`,
		`{"tool":"system.whoami","purpose":"system.whoami","target":"https://attacker.example"}`,
		`{"tool":"admin.unapproved","purpose":"system.whoami"}`,
		`{"tool":"system.whoami","purpose":"delete.everything"}`,
		`{"tool":"system.whoami","purpose":"system.whoami"}` + strings.Repeat(" ", 4097),
	} {
		t.Run(body, func(t *testing.T) {
			invoker := &fakeInvoker{}
			flow := newFlowWithInteractions(t, invoker)
			_, _, request := authenticatedInteractionRequest(t, flow, body)
			response := httptest.NewRecorder()
			flow.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || invoker.userToken != "" {
				t.Fatalf("override reached credential use: status=%d token=%q", response.Code, invoker.userToken)
			}
		})
	}
}

func TestInteractionRejectsMissingSessionWrongCSRFAndFailure(t *testing.T) {
	invoker := &fakeInvoker{}
	flow := newFlowWithInteractions(t, invoker)
	missing := httptest.NewRequest(http.MethodPost, "https://app.example/api/interactions", strings.NewReader(`{"tool":"system.whoami","purpose":"system.whoami"}`))
	missing.Header.Set("Content-Type", "application/json")
	missingResponse := httptest.NewRecorder()
	flow.handler.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing session status = %d", missingResponse.Code)
	}
	_, _, request := authenticatedInteractionRequest(t, flow, `{"tool":"system.whoami","purpose":"system.whoami"}`)
	request.Header.Set("X-CSRF-Token", "forged")
	csrfResponse := httptest.NewRecorder()
	flow.handler.ServeHTTP(csrfResponse, request)
	if csrfResponse.Code != http.StatusUnauthorized || invoker.userToken != "" {
		t.Fatalf("wrong CSRF reached invocation: %d", csrfResponse.Code)
	}
	invoker.err = context.DeadlineExceeded
	failedResponse := httptest.NewRecorder()
	flowForFailure := newFlowWithInteractions(t, invoker)
	_, _, failedRequest := authenticatedInteractionRequest(t, flowForFailure, `{"tool":"system.whoami","purpose":"system.whoami"}`)
	flowForFailure.handler.ServeHTTP(failedResponse, failedRequest)
	if failedResponse.Code != http.StatusBadGateway || strings.Contains(failedResponse.Body.String(), "DeadlineExceeded") {
		t.Fatalf("downstream failure not safely contained: %d %s", failedResponse.Code, failedResponse.Body.String())
	}
}

func TestAuditQueriesUseOnlyAuthenticatedSessionUser(t *testing.T) {
	reader := &fakeAuditReader{}
	flow := newFlowWithServices(t, nil, reader)
	callback := flow.callback(t, flow.state, nil)
	cookie := callback.Result().Cookies()[0]
	list := httptest.NewRequest(http.MethodGet, "https://app.example/api/interactions?user_id=attacker", nil)
	list.AddCookie(cookie)
	listed := httptest.NewRecorder()
	flow.handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK || reader.user != "user-123" || strings.Contains(listed.Body.String(), "attacker") {
		t.Fatalf("audit query used browser ownership: %d user=%q body=%s", listed.Code, reader.user, listed.Body.String())
	}
	guessed := httptest.NewRequest(http.MethodGet, "https://app.example/api/interactions/other-user-record", nil)
	guessed.AddCookie(cookie)
	guessedResult := httptest.NewRecorder()
	flow.handler.ServeHTTP(guessedResult, guessed)
	if guessedResult.Code != http.StatusNotFound || reader.user != "user-123" {
		t.Fatalf("guessed record was not same-user filtered: %d user=%q", guessedResult.Code, reader.user)
	}
}

func TestNewRejectsMismatchedRuntimeRoutesAndEndpointQueries(t *testing.T) {
	flow := newFlow(t)
	base := flow.handler.config
	for name, mutate := range map[string]func(*Config){
		"callback path": func(config *Config) { config.RedirectURI = "https://app.example/other-callback" },
		"public path":   func(config *Config) { config.PublicOrigin = "https://app.example/prefix" },
		"endpoint query": func(config *Config) {
			config.AuthorizationEndpoint += "?client=attacker"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("ambiguous browser runtime route accepted")
			}
		})
	}
}
