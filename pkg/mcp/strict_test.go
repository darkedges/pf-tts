package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/middleware"
	"example.com/workload-agent-identity/pkg/transaction"
)

type recordingStrictAuthorizer struct {
	called bool
	err    error
	value  identity.RequestIdentityContext
}

type strictContextVerifier struct{}

func (strictContextVerifier) Verify(context.Context, string) (transaction.TxnTokenClaims, error) {
	now := time.Now().UTC().Truncate(time.Second)
	return transaction.TxnTokenClaims{
		Issuer: "https://pf.example/tts", Subject: "user", Audience: "example.org", TransactionID: "txn",
		Scope: []string{"mcp.system.whoami"}, RequestingWorkloadID: "spiffe://example.org/agent/demo", IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
		TransactionContext: transaction.TransactionContext{WAI: transaction.WAITransactionContext{Version: 1, Target: "demo", Tool: "system.whoami", Agent: transaction.WAIAgentContext{ID: "urn:agent:demo", InstanceID: "instance", WorkloadID: "spiffe://example.org/agent/demo"}}},
	}, nil
}

func (a *recordingStrictAuthorizer) Authorize(_ context.Context, value identity.RequestIdentityContext, _, _ string) error {
	a.called = true
	a.value = value
	return a.err
}

func strictMCPContext(t *testing.T, raw string) context.Context {
	t.Helper()
	verifier := strictContextVerifier{}
	strict, err := middleware.NewStrictTxnMiddleware(middleware.StrictTxnMiddlewareConfig{Verifier: verifier, MaximumTokenBytes: 1024, AllowedCallers: map[string]struct{}{"spiffe://example.org/agent/demo": {}}, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/", nil)
	request.Header.Set(transaction.TxnTokenHeader, raw)
	spiffeURI, _ := url.Parse("spiffe://example.org/agent/demo")
	certificate := &x509.Certificate{URIs: []*url.URL{spiffeURI}}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	var captured context.Context
	strict.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { captured = r.Context() })).ServeHTTP(httptest.NewRecorder(), request)
	if captured == nil {
		t.Fatal("could not construct verified strict context")
	}
	return captured
}

func TestSignedRouteAuthorizerRequiresExactSignedTargetAndTool(t *testing.T) {
	inner := &recordingStrictAuthorizer{}
	authorizer, err := NewSignedRouteAuthorizer(inner)
	if err != nil {
		t.Fatal(err)
	}
	value := identity.RequestIdentityContext{User: identity.UserIdentity{ID: "user"}}
	if err := authorizer.Authorize(strictMCPContext(t, "header.payload.signature"), value, "demo", "system.whoami"); err != nil || !inner.called || !reflect.DeepEqual(inner.value, value) {
		t.Fatal("exact signed route was not delegated unchanged")
	}
}

func TestSignedRouteAuthorizerFailsClosed(t *testing.T) {
	tests := map[string]struct {
		ctx    context.Context
		target string
		tool   string
		deny   error
	}{
		"missing route":     {context.Background(), "demo", "system.whoami", nil},
		"empty target":      {strictMCPContext(t, "header.payload.signature"), "", "system.whoami", nil},
		"target mismatch":   {strictMCPContext(t, "header.payload.signature"), "other", "system.whoami", nil},
		"tool mismatch":     {strictMCPContext(t, "header.payload.signature"), "demo", "customer.get", nil},
		"underlying denial": {strictMCPContext(t, "header.payload.signature"), "demo", "system.whoami", errors.New("policy detail")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inner := &recordingStrictAuthorizer{err: test.deny}
			authorizer, _ := NewSignedRouteAuthorizer(inner)
			if err := authorizer.Authorize(test.ctx, identity.RequestIdentityContext{}, test.target, test.tool); !errors.Is(err, ErrStrictTransactionDenied) || strings.Contains(err.Error(), "policy detail") {
				t.Fatalf("unsafe route accepted or leaked: %v", err)
			}
			shouldCall := test.deny != nil
			if inner.called != shouldCall {
				t.Fatalf("underlying authorizer called=%v want=%v", inner.called, shouldCall)
			}
		})
	}
	cancelled, cancel := context.WithCancel(strictMCPContext(t, "header.payload.signature"))
	cancel()
	inner := &recordingStrictAuthorizer{}
	authorizer, _ := NewSignedRouteAuthorizer(inner)
	if err := authorizer.Authorize(cancelled, identity.RequestIdentityContext{}, "demo", "system.whoami"); !errors.Is(err, ErrStrictTransactionDenied) || inner.called {
		t.Fatal("cancelled authorization was delegated")
	}
	if _, err := NewSignedRouteAuthorizer(nil); !errors.Is(err, ErrStrictTransactionDenied) {
		t.Fatal("nil underlying authorizer accepted")
	}
}

func TestPropagateVerifiedTxnTokenUsesOnlyTrustedContext(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://mcp.example/", nil)
	if err := PropagateVerifiedTxnToken(strictMCPContext(t, "header.payload.signature"), request, 1024); err != nil {
		t.Fatal(err)
	}
	if values := request.Header.Values(transaction.TxnTokenHeader); len(values) != 1 || values[0] != "header.payload.signature" || request.Header.Get("Authorization") != "" {
		t.Fatalf("unexpected strict propagation: %#v", request.Header)
	}
}

func TestPropagateVerifiedTxnTokenFailsWithoutMutationOrLeak(t *testing.T) {
	tests := map[string]struct {
		ctx     context.Context
		request *http.Request
		bound   int
	}{
		"missing trusted context": {context.Background(), requestWithHeaders(nil), 1024},
		"existing bearer":         {strictMCPContext(t, "header.payload.signature"), requestWithHeaders(http.Header{"Authorization": []string{"Bearer legacy"}}), 1024},
		"existing txn token":      {strictMCPContext(t, "header.payload.signature"), requestWithHeaders(http.Header{transaction.TxnTokenHeader: []string{"other.token.value"}}), 1024},
		"non-positive bound":      {strictMCPContext(t, "header.payload.signature"), requestWithHeaders(nil), 0},
		"nil request":             {strictMCPContext(t, "header.payload.signature"), nil, 1024},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var before http.Header
			if test.request != nil {
				before = test.request.Header.Clone()
			}
			err := PropagateVerifiedTxnToken(test.ctx, test.request, test.bound)
			if !errors.Is(err, ErrStrictTransactionDenied) || strings.Contains(err.Error(), "header.payload.signature") || (test.request != nil && !reflect.DeepEqual(before, test.request.Header)) {
				t.Fatalf("failure mutated or leaked: err=%v headers=%#v", err, test.request)
			}
		})
	}
}

func requestWithHeaders(header http.Header) *http.Request {
	request, _ := http.NewRequest(http.MethodPost, "https://mcp.example/", nil)
	if header != nil {
		request.Header = header
	}
	return request
}
