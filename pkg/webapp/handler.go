package webapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrInvalidConfiguration = errors.New("invalid web application configuration")

type IDTokenVerifier interface {
	VerifyIDToken(context.Context, string, string, string) (string, error)
}

type Config struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	RedirectURI           string
	PublicOrigin          string
	ClientID              string
	ClientSecret          string
	Scopes                []string
	CookieName            string
	SessionTTL            time.Duration
	PreAuthTTL            time.Duration
	MaximumSessions       int
	HTTPClient            *http.Client
	Verifier              IDTokenVerifier
	Now                   func() time.Time
	Random                io.Reader
}

type preAuth struct {
	nonce, verifier string
	expires         time.Time
}

type session struct {
	subject, accessToken, csrf string
	expires                    time.Time
}

type Handler struct {
	config   Config
	mu       sync.Mutex
	preAuth  map[string]preAuth
	sessions map[string]session
	mux      *http.ServeMux
}

func New(config Config) (*Handler, error) {
	authURL, authErr := secureURL(config.AuthorizationEndpoint)
	tokenURL, tokenErr := secureURL(config.TokenEndpoint)
	redirectURL, redirectErr := secureURL(config.RedirectURI)
	publicURL, publicErr := secureURL(config.PublicOrigin)
	if authErr != nil || tokenErr != nil || redirectErr != nil || publicErr != nil ||
		authURL.Scheme != tokenURL.Scheme || authURL.Host != tokenURL.Host ||
		redirectURL.Scheme != publicURL.Scheme || redirectURL.Host != publicURL.Host ||
		strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" ||
		len(config.Scopes) == 0 || !contains(config.Scopes, "openid") ||
		!strings.HasPrefix(config.CookieName, "__Host-") || config.SessionTTL <= 0 ||
		config.PreAuthTTL <= 0 || config.MaximumSessions <= 0 || config.HTTPClient == nil ||
		config.HTTPClient.Timeout <= 0 || config.Verifier == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	h := &Handler{config: config, preAuth: make(map[string]preAuth), sessions: make(map[string]session), mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /login", h.login)
	h.mux.HandleFunc("GET /oauth/callback", h.callback)
	h.mux.HandleFunc("GET /api/session", h.getSession)
	h.mux.HandleFunc("POST /logout", h.logout)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	state, err := h.randomID()
	if err != nil {
		h.serverError(w)
		return
	}
	nonce, err := h.randomID()
	if err != nil {
		h.serverError(w)
		return
	}
	verifier, err := h.randomID()
	if err != nil {
		h.serverError(w)
		return
	}
	now := h.config.Now()
	h.mu.Lock()
	h.purgeLocked(now)
	if len(h.preAuth) >= h.config.MaximumSessions {
		h.mu.Unlock()
		h.serverError(w)
		return
	}
	h.preAuth[state] = preAuth{nonce: nonce, verifier: verifier, expires: now.Add(h.config.PreAuthTTL)}
	h.mu.Unlock()

	endpoint, _ := url.Parse(h.config.AuthorizationEndpoint)
	query := endpoint.Query()
	query.Set("response_type", "code")
	query.Set("client_id", h.config.ClientID)
	query.Set("redirect_uri", h.config.RedirectURI)
	query.Set("scope", strings.Join(h.config.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	challenge := sha256.Sum256([]byte(verifier))
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()
	http.Redirect(w, r, endpoint.String(), http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	state, okState := exactlyOne(r.URL.Query(), "state")
	code, okCode := exactlyOne(r.URL.Query(), "code")
	if !okState || !okCode || len(r.URL.Query()["error"]) != 0 {
		h.unauthorized(w)
		return
	}
	now := h.config.Now()
	h.mu.Lock()
	h.purgeLocked(now)
	flow, ok := h.preAuth[state]
	delete(h.preAuth, state) // consume once, including failed exchanges
	h.mu.Unlock()
	if !ok || !now.Before(flow.expires) {
		h.unauthorized(w)
		return
	}
	tokens, err := h.exchange(r.Context(), code, flow.verifier)
	if err != nil || tokens.RefreshToken != "" {
		h.unauthorized(w)
		return
	}
	subject, err := h.config.Verifier.VerifyIDToken(r.Context(), tokens.IDToken, h.config.ClientID, flow.nonce)
	if err != nil || strings.TrimSpace(subject) == "" {
		h.unauthorized(w)
		return
	}
	sessionID, err := h.randomID()
	if err != nil {
		h.serverError(w)
		return
	}
	csrf, err := h.randomID()
	if err != nil {
		h.serverError(w)
		return
	}
	h.mu.Lock()
	h.purgeLocked(now)
	if len(h.sessions) >= h.config.MaximumSessions {
		h.mu.Unlock()
		h.serverError(w)
		return
	}
	h.sessions[sessionID] = session{subject: subject, accessToken: tokens.AccessToken, csrf: csrf, expires: now.Add(h.config.SessionTTL)}
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.config.CookieName, Value: sessionID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(h.config.SessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (h *Handler) exchange(ctx context.Context, code, verifier string) (tokenResponse, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.config.RedirectURI}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, errors.New("token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(h.config.ClientID, h.config.ClientSecret)
	resp, err := h.config.HTTPClient.Do(req)
	if err != nil {
		return tokenResponse{}, errors.New("token request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, errors.New("token endpoint rejected request")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return tokenResponse{}, errors.New("invalid token response")
	}
	var result tokenResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(result.AccessToken) == "" || strings.TrimSpace(result.IDToken) == "" || !strings.EqualFold(result.TokenType, "Bearer") {
		return tokenResponse{}, errors.New("invalid token response")
	}
	return result, nil
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	_, current, ok := h.authenticate(r)
	if !ok {
		h.unauthorized(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Subject   string `json:"subject"`
		CSRFToken string `json:"csrf_token"`
	}{current.subject, current.csrf})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	id, current, ok := h.authenticate(r)
	if !ok || r.Header.Get("Origin") != strings.TrimSuffix(h.config.PublicOrigin, "/") || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(current.csrf)) != 1 {
		h.unauthorized(w)
		return
	}
	h.mu.Lock()
	delete(h.sessions, id)
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.config.CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authenticate(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie(h.config.CookieName)
	if err != nil || cookie.Value == "" {
		return "", session{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.config.Now()
	h.purgeLocked(now)
	current, ok := h.sessions[cookie.Value]
	return cookie.Value, current, ok && now.Before(current.expires)
}

func (h *Handler) purgeLocked(now time.Time) {
	for key, value := range h.preAuth {
		if !now.Before(value.expires) {
			delete(h.preAuth, key)
		}
	}
	for key, value := range h.sessions {
		if !now.Before(value.expires) {
			delete(h.sessions, key)
		}
	}
}

func (h *Handler) randomID() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(h.config.Random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func exactlyOne(values url.Values, key string) (string, bool) {
	items := values[key]
	returnValue := ""
	if len(items) == 1 {
		returnValue = strings.TrimSpace(items[0])
	}
	return returnValue, len(items) == 1 && returnValue != ""
}

func secureURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrInvalidConfiguration
	}
	return parsed, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (h *Handler) unauthorized(w http.ResponseWriter) {
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}
func (h *Handler) serverError(w http.ResponseWriter) {
	http.Error(w, "request failed", http.StatusInternalServerError)
}
