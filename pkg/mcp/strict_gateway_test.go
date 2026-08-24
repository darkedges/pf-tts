package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/transaction"
)

const strictGatewayToken = "header.payload.signature"

type strictGatewayAuthorizer struct {
	called bool
	err    error
}

func (a *strictGatewayAuthorizer) Authorize(context.Context, identity.RequestIdentityContext, string, string) error {
	a.called = true
	return a.err
}

func strictGatewayRequest(t *testing.T, tool string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/mcp", nil)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", tool)
	request.Header.Set(transaction.TxnTokenHeader, "untrusted-inbound.must-not.be-copied")
	return request.WithContext(strictMCPContext(t, strictGatewayToken))
}

func TestStrictGatewayForwardsOneVerifiedTxnTokenAfterSignedAuthorization(t *testing.T) {
	called := false
	downstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		called = true
		values := request.Header.Values(transaction.TxnTokenHeader)
		if len(values) != 1 || values[0] != strictGatewayToken || request.Header.Get("Authorization") != "" || request.Header.Get("Mcp-Method") != "tools/call" || request.Header.Get("Mcp-Name") != "system.whoami" {
			t.Errorf("strict downstream headers mismatch: %#v", request.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer downstream.Close()
	downstream.Client().Timeout = time.Second
	endpoint, _ := url.Parse(downstream.URL)
	authorizer := &strictGatewayAuthorizer{}
	gateway, err := NewStrictGatewayWithAuthorizer(downstream.Client(), []Target{{Name: "demo", URL: endpoint, Tools: map[string]struct{}{"system.whoami": {}}}}, authorizer, &gatewayAuditSink{}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, strictGatewayRequest(t, "system.whoami"))
	if recorder.Code != http.StatusNoContent || !called || !authorizer.called {
		t.Fatalf("strict route failed: status=%d downstream=%v policy=%v", recorder.Code, called, authorizer.called)
	}
}

func TestStrictGatewayFailsBeforeDownstream(t *testing.T) {
	downstreamCalls := 0
	downstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { downstreamCalls++ }))
	defer downstream.Close()
	downstream.Client().Timeout = time.Second
	endpoint, _ := url.Parse(downstream.URL)

	tests := map[string]struct {
		request    func(*testing.T) *http.Request
		authorizer *strictGatewayAuthorizer
	}{
		"signed tool mismatch": {func(t *testing.T) *http.Request { return strictGatewayRequest(t, "customer.get") }, &strictGatewayAuthorizer{}},
		"policy denial":        {func(t *testing.T) *http.Request { return strictGatewayRequest(t, "system.whoami") }, &strictGatewayAuthorizer{err: errors.New("policy secret")}},
		"missing context": {func(*testing.T) *http.Request {
			request := httptest.NewRequest(http.MethodPost, "https://gateway.example/mcp", nil)
			request.Header.Set("Mcp-Method", "tools/call")
			request.Header.Set("Mcp-Name", "system.whoami")
			return request
		}, &strictGatewayAuthorizer{}},
		"legacy authorization": {func(t *testing.T) *http.Request {
			request := strictGatewayRequest(t, "system.whoami")
			request.Header.Set("Authorization", "Bearer legacy-secret")
			return request
		}, &strictGatewayAuthorizer{}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gateway, err := NewStrictGatewayWithAuthorizer(downstream.Client(), []Target{{Name: "demo", URL: endpoint, Tools: map[string]struct{}{"system.whoami": {}, "customer.get": {}}}}, test.authorizer, &gatewayAuditSink{}, 1024)
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			gateway.ServeHTTP(recorder, test.request(t))
			if recorder.Code < 400 || downstreamCalls != 0 || strings.Contains(recorder.Body.String(), "legacy-secret") || strings.Contains(recorder.Body.String(), strictGatewayToken) {
				t.Fatalf("strict failure leaked or forwarded: status=%d calls=%d body=%q", recorder.Code, downstreamCalls, recorder.Body.String())
			}
		})
	}
}

func TestStrictGatewayRejectsInvalidConstruction(t *testing.T) {
	endpoint, _ := url.Parse("https://mcp.example/mcp")
	targets := []Target{{Name: "demo", URL: endpoint, Tools: map[string]struct{}{"system.whoami": {}}}}
	client := &http.Client{Timeout: time.Second}
	for name, build := range map[string]func() error{
		"nil authorizer": func() error {
			_, err := NewStrictGatewayWithAuthorizer(client, targets, nil, &gatewayAuditSink{}, 1024)
			return err
		},
		"nil audit": func() error {
			_, err := NewStrictGatewayWithAuthorizer(client, targets, &strictGatewayAuthorizer{}, nil, 1024)
			return err
		},
		"invalid bound": func() error {
			_, err := NewStrictGatewayWithAuthorizer(client, targets, &strictGatewayAuthorizer{}, &gatewayAuditSink{}, 0)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatal("invalid strict gateway configuration accepted")
			}
		})
	}
}
