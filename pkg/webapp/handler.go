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
	"regexp"
	"strings"
	"sync"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
)

var ErrInvalidConfiguration = errors.New("invalid web application configuration")

type IDTokenVerifier interface {
	VerifyIDToken(context.Context, string, string, string) (string, error)
}

// Invocation is what an invoker reports back about one completed call. The
// request and response are shown to the signed-in user, so neither may contain
// token material; the transaction token travels in a header and never appears
// in either.
type Invocation struct {
	TransactionID string
	Request       string
	Response      string
}

type InteractionInvoker interface {
	Invoke(context.Context, string, string, string) (Invocation, error)
}

type AllowedInteraction struct {
	Tool    string
	Purpose string
}

type AuditReader interface {
	ListByUser(context.Context, string) ([]audit.Record, error)
	GetByUser(context.Context, string, string) (audit.Record, error)
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
	// MaximumDisplayBytes bounds what an invocation may render into a browser.
	MaximumDisplayBytes int
	HTTPClient          *http.Client
	Verifier            IDTokenVerifier
	Interactions        InteractionInvoker
	AllowedInteractions []AllowedInteraction
	Audit               AuditReader
	Now                 func() time.Time
	Random              io.Reader
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
	allowed  map[AllowedInteraction]struct{}
	mux      *http.ServeMux
}

func New(config Config) (*Handler, error) {
	_, authErr := secureURL(config.AuthorizationEndpoint)
	_, tokenErr := secureURL(config.TokenEndpoint)
	redirectURL, redirectErr := secureURL(config.RedirectURI)
	publicURL, publicErr := secureURL(config.PublicOrigin)
	if authErr != nil || tokenErr != nil || redirectErr != nil || publicErr != nil ||
		redirectURL.Scheme != publicURL.Scheme || redirectURL.Host != publicURL.Host ||
		redirectURL.Path != "/oauth/callback" || publicURL.Path != "" && publicURL.Path != "/" ||
		strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" ||
		len(config.Scopes) == 0 || !contains(config.Scopes, "openid") ||
		!strings.HasPrefix(config.CookieName, "__Host-") || config.SessionTTL <= 0 ||
		config.PreAuthTTL <= 0 || config.MaximumSessions <= 0 || config.MaximumDisplayBytes <= 0 || config.HTTPClient == nil ||
		config.HTTPClient.Timeout <= 0 || config.Verifier == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	allowed := make(map[AllowedInteraction]struct{}, len(config.AllowedInteractions))
	for _, interaction := range config.AllowedInteractions {
		if strings.TrimSpace(interaction.Tool) != interaction.Tool || strings.TrimSpace(interaction.Purpose) != interaction.Purpose || interaction.Tool == "" || interaction.Purpose == "" {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := allowed[interaction]; exists {
			return nil, ErrInvalidConfiguration
		}
		allowed[interaction] = struct{}{}
	}
	if (config.Interactions == nil) != (len(allowed) == 0) {
		return nil, ErrInvalidConfiguration
	}
	h := &Handler{config: config, preAuth: make(map[string]preAuth), sessions: make(map[string]session), allowed: allowed, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /login", h.login)
	h.mux.HandleFunc("GET /oauth/callback", h.callback)
	h.mux.HandleFunc("GET /api/session", h.getSession)
	h.mux.HandleFunc("POST /logout", h.logout)
	h.mux.HandleFunc("GET /{$}", h.static("static/index.html", "text/html; charset=utf-8"))
	h.mux.HandleFunc("GET /app.css", h.static("static/app.css", "text/css; charset=utf-8"))
	h.mux.HandleFunc("GET /app.js", h.static("static/app.js", "text/javascript; charset=utf-8"))
	if config.Interactions != nil {
		h.mux.HandleFunc("POST /api/interactions", h.invokeInteraction)
	}
	if config.Audit != nil {
		h.mux.HandleFunc("GET /api/interactions", h.listInteractions)
		h.mux.HandleFunc("GET /api/interactions/{id}", h.getInteraction)
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("X-Frame-Options", "DENY")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) static(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		content, err := staticFiles.ReadFile(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(content)
	}
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
	if !ok || !h.validCSRF(r, current) {
		h.unauthorized(w)
		return
	}
	h.mu.Lock()
	delete(h.sessions, id)
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.config.CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) invokeInteraction(w http.ResponseWriter, r *http.Request) {
	_, current, ok := h.authenticate(r)
	if !ok || !h.validCSRF(r, current) {
		h.unauthorized(w)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		h.badRequest(w)
		return
	}
	var request struct {
		Tool    string `json:"tool"`
		Purpose string `json:"purpose"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (4<<10)+1))
	if err != nil || len(body) > 4<<10 {
		h.badRequest(w)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		h.badRequest(w)
		return
	}
	interaction := AllowedInteraction{Tool: request.Tool, Purpose: request.Purpose}
	if _, allowed := h.allowed[interaction]; !allowed {
		h.badRequest(w)
		return
	}
	invocation, err := h.config.Interactions.Invoke(r.Context(), current.accessToken, interaction.Purpose, interaction.Tool)
	if err != nil || strings.TrimSpace(invocation.TransactionID) == "" {
		h.unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		TransactionID string `json:"transaction_id"`
		Status        string `json:"status"`
		Request       string `json:"request,omitempty"`
		Response      string `json:"response,omitempty"`
		Withheld      string `json:"withheld,omitempty"`
	}{
		TransactionID: invocation.TransactionID, Status: "completed",
		Request:  displayable(invocation.Request, h.config.MaximumDisplayBytes),
		Response: displayable(invocation.Response, h.config.MaximumDisplayBytes),
		Withheld: withheldReason(invocation, h.config.MaximumDisplayBytes),
	})
}

func (h *Handler) listInteractions(w http.ResponseWriter, r *http.Request) {
	_, current, ok := h.authenticate(r)
	if !ok {
		h.unauthorized(w)
		return
	}
	records, err := h.config.Audit.ListByUser(r.Context(), current.subject)
	if err != nil {
		h.unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(records)
}

func (h *Handler) getInteraction(w http.ResponseWriter, r *http.Request) {
	_, current, ok := h.authenticate(r)
	if !ok {
		h.unauthorized(w)
		return
	}
	record, err := h.config.Audit.GetByUser(r.Context(), current.subject, r.PathValue("id"))
	if errors.Is(err, audit.ErrRecordMissing) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		h.unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(record)
}

// compactJWS matches a three-segment compact serialization. The strict call
// chain returns verified identity metadata rather than tokens, so a match here
// means something upstream changed. The body is withheld rather than shown,
// because the workbench renders it straight into a browser.
var compactJWS = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

func displayable(body string, maximum int) string {
	if body == "" || len(body) > maximum || compactJWS.MatchString(body) {
		return ""
	}
	return body
}

func withheldReason(invocation Invocation, maximum int) string {
	for _, body := range []string{invocation.Request, invocation.Response} {
		if body == "" {
			continue
		}
		if compactJWS.MatchString(body) {
			return "withheld: the exchange contained token material"
		}
		if len(body) > maximum {
			return "withheld: the exchange exceeded the display bound"
		}
	}
	return ""
}

func (h *Handler) validCSRF(r *http.Request, current session) bool {
	return r.Header.Get("Origin") == strings.TrimSuffix(h.config.PublicOrigin, "/") &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(current.csrf)) == 1
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
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
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
func (h *Handler) badRequest(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusBadRequest)
}
func (h *Handler) unavailable(w http.ResponseWriter) {
	http.Error(w, "interaction unavailable", http.StatusBadGateway)
}
