package middleware

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/transaction"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var ErrUnauthenticated = errors.New("request authentication failed")

type verifiedTokenContextKey struct{}

func VerifiedTransactionToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(verifiedTokenContextKey{}).(string)
	return token, ok && token != ""
}

type CallerPolicy interface {
	Authorize(transaction.Claims, string) error
}
type Middleware struct {
	Verifier                  transaction.Verifier
	Audience                  string
	Callers                   CallerPolicy
	SPIFFEMTLSAlreadyVerified bool
	Audit                     audit.Sink
	Target                    string
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Verifier == nil || m.Callers == nil || m.Audience == "" {
			http.Error(w, "authentication unavailable", http.StatusInternalServerError)
			return
		}
		raw, err := bearer(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := m.Verifier.Verify(r.Context(), raw, m.Audience)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		caller, err := immediateCallerSPIFFEID(r.TLS, m.SPIFFEMTLSAlreadyVerified)
		if err != nil || m.Callers.Authorize(claims, caller) != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		user, e1 := identity.NewUserIdentity(claims.Subject)
		agent, e2 := identity.NewAgentIdentity(claims.AgentID, claims.AgentInstanceID)
		workload, e3 := identity.NewWorkloadIdentity(claims.WorkloadID)
		immediate, e4 := identity.NewWorkloadIdentity(caller)
		txn, e5 := identity.NewTransactionIdentity(claims.TransactionID, claims.Purpose)
		auth, e6 := identity.NewAuthorizationContext(claims.Scope)
		if errors.Join(e1, e2, e3, e4, e5, e6) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		value, err := identity.NewRequestIdentityContext(user, agent, workload, immediate, txn, auth)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if m.Audit != nil {
			err = m.Audit.Write(audit.Event{
				Type: audit.TransactionVerifySucceeded, TransactionID: claims.TransactionID,
				UserID: claims.Subject, AgentID: claims.AgentID, TransactionWorkloadID: claims.WorkloadID,
				ImmediateCallerSPIFFEID: caller, Target: m.Target, Decision: "allow", ReasonCode: "verified", ProtocolMethod: r.Method, Purpose: claims.Purpose,
			})
			if err != nil {
				http.Error(w, "audit unavailable", http.StatusInternalServerError)
				return
			}
		}
		ctx := identity.WithContext(r.Context(), value)
		ctx = context.WithValue(ctx, verifiedTokenContextKey{}, raw)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearer(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrUnauthenticated
	}
	return parts[1], nil
}

func ImmediateCallerSPIFFEID(state *tls.ConnectionState) (string, error) {
	return immediateCallerSPIFFEID(state, false)
}

func immediateCallerSPIFFEID(state *tls.ConnectionState, spiffeMTLSAlreadyVerified bool) (string, error) {
	if state == nil || len(state.PeerCertificates) == 0 || (!spiffeMTLSAlreadyVerified && len(state.VerifiedChains) == 0) {
		return "", ErrUnauthenticated
	}
	ids := state.PeerCertificates[0].URIs
	if len(ids) != 1 {
		return "", ErrUnauthenticated
	}
	id, err := spiffeid.FromURI(ids[0])
	if err != nil {
		return "", ErrUnauthenticated
	}
	return id.String(), nil
}
