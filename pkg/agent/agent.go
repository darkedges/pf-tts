package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/transaction"
)

type Mode string

const (
	Normal        Mode = "normal"
	SpoofAgent    Mode = "spoof-agent"
	WrongAudience Mode = "wrong-audience"
	ExpiredToken  Mode = "expired-token"
	DirectToAPI   Mode = "direct-to-api"
	UnapprovedMCP Mode = "unapproved-mcp"
)

type Runner struct {
	SPIFFE                                                                         corespiffe.Provider
	Exchange                                                                       pingfederate.TokenExchanger
	Verifier                                                                       transaction.Verifier
	Audit                                                                          audit.Sink
	HTTP                                                                           *http.Client
	ActorAudience, ExchangeAudience, TransactionAudience, GatewayURL, DirectAPIURL string
	AgentID, WorkloadID, AuditTarget                                               string
}

func (r Runner) Run(ctx context.Context, userToken, purpose string, mode Mode) error {
	_, err := r.invoke(ctx, userToken, purpose, "system.whoami", mode)
	return err
}

// Invoke performs the production delegated flow for a server-selected tool and
// returns only the verified transaction ID. It never returns either token.
func (r Runner) Invoke(ctx context.Context, userToken, purpose, tool string) (string, error) {
	return r.invoke(ctx, userToken, purpose, tool, Normal)
}

func (r Runner) invoke(ctx context.Context, userToken, purpose, tool string, mode Mode) (string, error) {
	if userToken == "" || purpose == "" {
		return "", errors.New("user token and constrained purpose required")
	}
	if strings.TrimSpace(tool) == "" {
		return "", errors.New("constrained tool required")
	}
	if mode == SpoofAgent {
		return "", errors.New("spoof-agent rejected locally: logical AgentID is not a client-controlled exchange parameter")
	}
	if mode == ExpiredToken {
		return "", errors.New("expired-token rejected locally: agent cannot mint transaction tokens")
	}
	svid, err := r.SPIFFE.FetchJWTSVID(ctx, []string{r.ActorAudience})
	if err != nil {
		return "", fmt.Errorf("fetch actor identity: %w", err)
	}
	aud := r.ExchangeAudience
	if mode == WrongAudience {
		aud = "intentionally-wrong-audience"
	}
	tx := newID()
	instance := newID()
	response, err := r.Exchange.Exchange(ctx, pingfederate.ExchangeRequest{SubjectToken: userToken, ActorToken: svid.Token, SubjectTokenType: pingfederate.AccessTokenType, ActorTokenType: pingfederate.JWTTokenType, Audience: aud, Scope: []string{"mcp:invoke"}, TransactionID: tx, TransactionPurpose: purpose, AgentInstanceID: instance})
	if err != nil {
		return "", err
	}
	if r.Verifier == nil || r.AgentID == "" || r.WorkloadID == "" {
		return "", errors.New("transaction verifier and trusted agent/workload bindings required")
	}
	claims, err := r.Verifier.Verify(ctx, response.AccessToken, r.TransactionAudience)
	if err != nil {
		return "", errors.New("issued transaction token verification failed")
	}
	if claims.AgentID != r.AgentID || claims.WorkloadID != r.WorkloadID || claims.Purpose != purpose {
		return "", errors.New("issued transaction identity binding mismatch")
	}
	tokenEvidence, err := audit.NewVerifiedTransactionTokenEvidence(response.AccessToken, claims)
	if err != nil {
		return "", errors.New("issued transaction token evidence invalid")
	}
	if r.Audit != nil {
		if err := r.Audit.Write(audit.Event{
			Type: audit.TransactionExchangeSucceeded, TransactionID: claims.TransactionID,
			UserID: claims.Subject, AgentID: claims.AgentID, TransactionWorkloadID: claims.WorkloadID,
			Target: r.AuditTarget, Decision: "allow", ReasonCode: "verified", ProtocolMethod: "token_exchange", Tool: tool, Purpose: purpose, Token: tokenEvidence,
		}); err != nil {
			return "", errors.New("audit unavailable")
		}
	}
	target := r.GatewayURL
	if mode == DirectToAPI {
		target = r.DirectAPIURL
	}
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, tool)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	req.Header.Set("Mcp-Method", "tools/call")
	if mode == UnapprovedMCP {
		req.Header.Set("Mcp-Name", "admin.unapproved")
	} else {
		req.Header.Set("Mcp-Name", tool)
	}
	result, err := r.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("invoke target: %w", err)
	}
	defer result.Body.Close()
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(result.Body, 128))
		reason := strings.TrimSpace(string(body))
		switch reason {
		case "route denied", "forbidden", "unauthorized":
			source := result.Header.Get("X-WAI-Response-Source")
			if source == "downstream" {
				return "", fmt.Errorf("target rejected request: status=%d reason=%s source=downstream", result.StatusCode, reason)
			}
			return "", fmt.Errorf("target rejected request: status=%d reason=%s", result.StatusCode, reason)
		default:
			return "", fmt.Errorf("target rejected request: status=%d", result.StatusCode)
		}
	}
	return claims.TransactionID, nil
}
func newID() string {
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic("cryptographic randomness unavailable")
	}
	return fmt.Sprintf("%013d-%s", time.Now().UnixMilli(), hex.EncodeToString(random[:]))
}
