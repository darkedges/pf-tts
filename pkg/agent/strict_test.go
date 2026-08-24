package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/transaction"
	"example.com/workload-agent-identity/pkg/ttsadapter"
)

type fakeStrictTokenVerifier struct {
	claims transaction.TxnTokenClaims
	err    error
}

func (v fakeStrictTokenVerifier) Verify(context.Context, string) (transaction.TxnTokenClaims, error) {
	return v.claims, v.err
}

func strictRunnerClaims() transaction.TxnTokenClaims {
	return transaction.TxnTokenClaims{
		TransactionID: "txn-test", RequestingWorkloadID: "spiffe://example.org/agent/demo", Scope: []string{"mcp.system.whoami"},
		TransactionContext: transaction.TransactionContext{WAI: transaction.WAITransactionContext{Target: "demo", Tool: "system.whoami", Agent: transaction.WAIAgentContext{ID: "urn:agent:demo"}}},
	}
}

func TestStrictRunnerRejectsConfiguredWorkloadMismatch(t *testing.T) {
	runner := StrictRunner{SPIFFE: fakeProvider{}, AdapterHTTP: &http.Client{Timeout: time.Second}, GatewayHTTP: &http.Client{Timeout: time.Second}, AdapterURL: "https://adapter.example", GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{claims: strictRunnerClaims()}, MaximumBytes: 1024, WorkloadID: "spiffe://example.org/agent/web-app", AgentID: "urn:agent:web-app"}
	if _, err := runner.Invoke(context.Background(), "user-secret", "system.whoami", "system.whoami"); !errors.Is(err, ErrStrictAgent) {
		t.Fatalf("configured workload mismatch was accepted: %v", err)
	}
}

func TestStrictRunnerUsesExactAdapterAndTxnTokenTransport(t *testing.T) {
	adapter := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://adapter.example/as/token.oauth2" || request.Header.Get("Authorization") != "" || request.ParseForm() != nil || request.Form.Get("subject_token") != "user-secret" || request.Form.Get("actor_token") != "actor-token" || request.Form.Get("requested_token_type") != ttsadapter.TransactionTokenType || request.Form.Get("audience") != "example.org" || request.Form.Get("scope") != "mcp.system.whoami" {
			t.Error("adapter request did not preserve exact strict exchange semantics")
		}
		body := `{"access_token":"header.payload.signature","issued_token_type":"` + ttsadapter.TransactionTokenType + `","token_type":"N_A","expires_in":20}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	gateway := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if values := request.Header.Values(transaction.TxnTokenHeader); len(values) != 1 || values[0] != "header.payload.signature" || request.Header.Get("Authorization") != "" || request.Header.Get("Mcp-Name") != "system.whoami" {
			t.Errorf("gateway strict transport mismatch: %#v", request.Header)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	runner := StrictRunner{SPIFFE: fakeProvider{}, AdapterHTTP: adapter, GatewayHTTP: gateway, AdapterURL: "https://adapter.example/as/token.oauth2", GatewayURL: "https://gateway.example/mcp", Verifier: fakeStrictTokenVerifier{claims: strictRunnerClaims()}, MaximumBytes: 16 << 10}
	if err := runner.Run(context.Background(), "user-secret"); err != nil {
		t.Fatal(err)
	}
}

func TestStrictRunnerFailsClosedWithoutCredentialLeak(t *testing.T) {
	validAdapter := func(body string) *http.Client {
		return &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	validBody := `{"access_token":"header.payload.signature","issued_token_type":"` + ttsadapter.TransactionTokenType + `","token_type":"N_A","expires_in":20}`
	tests := map[string]StrictRunner{
		"missing user token":  {},
		"malformed response":  {SPIFFE: fakeProvider{}, AdapterHTTP: validAdapter(`{`), GatewayHTTP: validAdapter(`{}`), AdapterURL: "https://adapter.example", GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{claims: strictRunnerClaims()}, MaximumBytes: 1024},
		"wrong outer type":    {SPIFFE: fakeProvider{}, AdapterHTTP: validAdapter(strings.Replace(validBody, `"N_A"`, `"Bearer"`, 1)), GatewayHTTP: validAdapter(`{}`), AdapterURL: "https://adapter.example", GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{claims: strictRunnerClaims()}, MaximumBytes: 1024},
		"wrong strict claims": {SPIFFE: fakeProvider{}, AdapterHTTP: validAdapter(validBody), GatewayHTTP: validAdapter(`{}`), AdapterURL: "https://adapter.example", GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{claims: transaction.TxnTokenClaims{}}, MaximumBytes: 1024},
		"verifier failure":    {SPIFFE: fakeProvider{}, AdapterHTTP: validAdapter(validBody), GatewayHTTP: validAdapter(`{}`), AdapterURL: "https://adapter.example", GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{err: errors.New("header.payload.signature user-secret")}, MaximumBytes: 1024},
	}
	for name, runner := range tests {
		t.Run(name, func(t *testing.T) {
			err := runner.Run(context.Background(), "user-secret")
			if !errors.Is(err, ErrStrictAgent) || strings.Contains(err.Error(), "user-secret") || strings.Contains(err.Error(), "header.payload.signature") {
				t.Fatalf("strict failure accepted or leaked: %v", err)
			}
		})
	}
}

func TestDecodeStrictAdapterResponseRejectsDuplicateUnknownAndOversized(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate": `{"access_token":"a.b.c","access_token":"d.e.f","issued_token_type":"` + ttsadapter.TransactionTokenType + `","token_type":"N_A","expires_in":20}`,
		"unknown":   `{"access_token":"a.b.c","issued_token_type":"` + ttsadapter.TransactionTokenType + `","token_type":"N_A","expires_in":20,"refresh_token":"secret"}`,
		"oversized": strings.Repeat("x", 1025),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictAdapterResponse(strings.NewReader(body), 1024); !errors.Is(err, ErrStrictAgent) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe adapter response accepted or leaked: %v", err)
			}
		})
	}
}

func TestStrictRunnerRejectsAdapterRedirect(t *testing.T) {
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("strict agent followed adapter redirect")
	}))
	defer redirectTarget.Close()
	adapter := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer adapter.Close()
	adapter.Client().Timeout = time.Second
	runner := StrictRunner{SPIFFE: fakeProvider{}, AdapterHTTP: adapter.Client(), GatewayHTTP: adapter.Client(), AdapterURL: adapter.URL, GatewayURL: "https://gateway.example", Verifier: fakeStrictTokenVerifier{claims: strictRunnerClaims()}, MaximumBytes: 1024}
	if err := runner.Run(context.Background(), "user-secret"); !errors.Is(err, ErrStrictAgent) {
		t.Fatalf("adapter redirect was not rejected: %v", err)
	}
}
