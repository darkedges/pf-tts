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
)

type fakeVerifier struct {
	expectedNonce string
	fail          bool
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
	handler, err := New(Config{AuthorizationEndpoint: tokenServer.URL + "/authorize", TokenEndpoint: tokenServer.URL + "/token", RedirectURI: "https://app.example/oauth/callback", PublicOrigin: "https://app.example", ClientID: "web-client", ClientSecret: "secret", Scopes: []string{"openid"}, CookieName: "__Host-wai_session", SessionTTL: time.Hour, PreAuthTTL: time.Minute, MaximumSessions: 10, HTTPClient: tokenServer.Client(), Verifier: verifier})
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
