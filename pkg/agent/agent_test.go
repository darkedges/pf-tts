package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/transaction"
)

type fakeProvider struct{}

func (fakeProvider) FetchJWTSVID(context.Context, []string) (corespiffe.JWTSVID, error) {
	return corespiffe.JWTSVID{Token: "actor-token", SPIFFEID: "spiffe://example.org/agent/demo"}, nil
}
func (fakeProvider) X509Source(context.Context) (corespiffe.X509Source, error) { return nil, nil }
func (fakeProvider) SPIFFEID() string                                          { return "spiffe://example.org/agent/demo" }
func (fakeProvider) Close() error                                              { return nil }

type fakeExchange struct{}

func (fakeExchange) Exchange(context.Context, pingfederate.ExchangeRequest) (pingfederate.ExchangeResponse, error) {
	return pingfederate.ExchangeResponse{AccessToken: "transaction-token", TokenType: "Bearer"}, nil
}

type fakeTransactionVerifier struct{ claims transaction.Claims }

func (v fakeTransactionVerifier) Verify(context.Context, string, string) (transaction.Claims, error) {
	return v.claims, nil
}

type fakeAuditSink struct{ err error }

func (s fakeAuditSink) Write(audit.Event) error { return s.err }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAttackModesFailBeforeCredentialUse(t *testing.T) {
	r := Runner{}
	for _, mode := range []Mode{SpoofAgent, ExpiredToken} {
		if err := r.Run(context.Background(), "user-secret", "customer.read", mode); err == nil {
			t.Fatalf("mode %s did not fail", mode)
		}
	}
}
func TestRequiredInput(t *testing.T) {
	if err := (Runner{}).Run(context.Background(), "", "customer.read", Normal); err == nil {
		t.Fatal("missing user token accepted")
	}
}

func validRunner(claims transaction.Claims, sink audit.Sink) Runner {
	return Runner{
		SPIFFE: fakeProvider{}, Exchange: fakeExchange{}, Verifier: fakeTransactionVerifier{claims: claims}, Audit: sink,
		HTTP: &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
		})},
		ActorAudience: "actor", ExchangeAudience: "mcp-gateway", TransactionAudience: "urn:wai:mcp-gateway",
		GatewayURL: "https://gateway", DirectAPIURL: "https://api", AgentID: "urn:agent:demo",
		WorkloadID: "spiffe://example.org/agent/demo", AuditTarget: "demo-agent",
	}
}

func TestRunnerRejectsVerifiedTokenWithForgedAgentBinding(t *testing.T) {
	claims := transaction.Claims{AgentID: "urn:agent:forged", WorkloadID: "spiffe://example.org/agent/demo", Purpose: "system.whoami"}
	if err := validRunner(claims, fakeAuditSink{}).Run(context.Background(), "user-token", "system.whoami", Normal); err == nil {
		t.Fatal("verified transaction token with forged logical agent binding accepted")
	}
}

func TestRunnerFailsClosedWhenVerifiedAuditCannotBeWritten(t *testing.T) {
	claims := transaction.Claims{Subject: "user", AgentID: "urn:agent:demo", WorkloadID: "spiffe://example.org/agent/demo", TransactionID: "tx", Purpose: "system.whoami"}
	err := validRunner(claims, fakeAuditSink{err: errors.New("unavailable")}).Run(context.Background(), "user-token", "system.whoami", Normal)
	if err == nil || err.Error() != "audit unavailable" {
		t.Fatalf("audit failure did not fail closed: %v", err)
	}
}
