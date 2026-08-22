package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/transaction"
)

type fakeVerifier struct {
	claims transaction.Claims
	err    error
	raw    string
}

func (f *fakeVerifier) Verify(_ context.Context, raw, _ string) (transaction.Claims, error) {
	f.raw = raw
	return f.claims, f.err
}

type exactCaller string

func (p exactCaller) Authorize(_ transaction.Claims, caller string) error {
	if caller != string(p) {
		return errors.New("denied")
	}
	return nil
}

func validMiddlewareClaims() transaction.Claims {
	now := time.Now()
	return transaction.Claims{Issuer: "https://pf", Subject: "user", Audience: []string{"mcp"}, JWTID: "jti", AgentID: "urn:agent:demo", AgentInstanceID: "instance", WorkloadID: "spiffe://example.org/agent/demo", TransactionID: "tx", Purpose: "customer.read", Scope: []string{"mcp:invoke"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
}
func tlsState(t *testing.T, ids ...string) *tls.ConnectionState {
	t.Helper()
	cert := &x509.Certificate{}
	for _, raw := range ids {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = append(cert.URIs, u)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
}

func TestMiddlewarePlacesVerifiedIdentityInContext(t *testing.T) {
	v := &fakeVerifier{claims: validMiddlewareClaims()}
	m := Middleware{Verifier: v, Audience: "mcp", Callers: exactCaller("spiffe://example.org/agent/demo")}
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := identity.FromContext(r.Context())
		if !ok || value.Transaction.ID != "tx" {
			t.Error("missing typed context")
		}
		if token, ok := VerifiedTransactionToken(r.Context()); !ok || token != "raw-transaction-secret" {
			t.Error("verified immutable transaction token missing from trusted context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "https://gateway/mcp", nil)
	req.Header.Set("Authorization", "Bearer raw-transaction-secret")
	req.TLS = tlsState(t, "spiffe://example.org/agent/demo")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	if v.raw != "raw-transaction-secret" {
		t.Fatal("verifier did not receive bearer token")
	}
}

func TestRejectedRequestNeverReceivesVerifiedTransactionToken(t *testing.T) {
	m := Middleware{Verifier: &fakeVerifier{err: errors.New("bad signature")}, Audience: "mcp", Callers: exactCaller("spiffe://example.org/agent/demo")}
	req := httptest.NewRequest(http.MethodGet, "https://gateway/mcp", nil)
	req.Header.Set("Authorization", "Bearer unverified-token")
	req.TLS = tlsState(t, "spiffe://example.org/agent/demo")
	rr := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := VerifiedTransactionToken(r.Context()); ok {
			t.Fatal("unverified token entered trusted context")
		}
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMiddlewareFailsClosed(t *testing.T) {
	base := validMiddlewareClaims()
	tests := []struct {
		name, auth string
		tls        *tls.ConnectionState
		claims     transaction.Claims
		policy     exactCaller
		want       int
	}{
		{"missing bearer", "", tlsState(t, "spiffe://example.org/agent/demo"), base, exactCaller("spiffe://example.org/agent/demo"), http.StatusUnauthorized},
		{"unverified TLS", "Bearer token", &tls.ConnectionState{}, base, exactCaller("spiffe://example.org/agent/demo"), http.StatusForbidden},
		{"ambiguous caller", "Bearer token", tlsState(t, "spiffe://example.org/a", "spiffe://example.org/b"), base, exactCaller("spiffe://example.org/a"), http.StatusForbidden},
		{"wrong caller", "Bearer token", tlsState(t, "spiffe://example.org/agent/other"), base, exactCaller("spiffe://example.org/agent/demo"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Middleware{Verifier: &fakeVerifier{claims: tt.claims}, Audience: "mcp", Callers: tt.policy}
			req := httptest.NewRequest(http.MethodGet, "https://gateway/mcp", nil)
			req.Header.Set("Authorization", tt.auth)
			req.TLS = tt.tls
			rr := httptest.NewRecorder()
			m.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler must not run") })).ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestImmediateCallerRejectsUnverifiedPeerUnlessSPIFFEMTLSAlreadyVerified(t *testing.T) {
	u, err := url.Parse("spiffe://example.org/agent/demo")
	if err != nil {
		t.Fatal(err)
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
	if _, err := ImmediateCallerSPIFFEID(state); err == nil {
		t.Fatal("unverified peer certificate accepted by default")
	}
	if got, err := immediateCallerSPIFFEID(state, true); err != nil || got != u.String() {
		t.Fatalf("SPIFFE-mTLS-authenticated peer was not accepted: got=%q err=%v", got, err)
	}
}
