package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/transaction"
)

type StrictTxnVerifier interface {
	Verify(context.Context, string) (transaction.TxnTokenClaims, error)
}

type SignedRoute struct {
	Target string
	Tool   string
}

type signedRouteContextKey struct{}

func VerifiedSignedRoute(ctx context.Context) (SignedRoute, bool) {
	route, ok := ctx.Value(signedRouteContextKey{}).(SignedRoute)
	return route, ok && route.Target != "" && route.Tool != ""
}

type StrictTxnMiddlewareConfig struct {
	Verifier                  StrictTxnVerifier
	MaximumTokenBytes         int
	AllowedCallers            map[string]struct{}
	SPIFFEMTLSAlreadyVerified bool
	Audit                     audit.Sink
	Service                   string
}

type StrictTxnMiddleware struct {
	config  StrictTxnMiddlewareConfig
	callers map[string]struct{}
}

func NewStrictTxnMiddleware(config StrictTxnMiddlewareConfig) (*StrictTxnMiddleware, error) {
	if config.Verifier == nil || config.MaximumTokenBytes <= 0 || len(config.AllowedCallers) == 0 || strings.TrimSpace(config.Service) == "" {
		return nil, errors.New("invalid strict transaction middleware configuration")
	}
	callers := make(map[string]struct{}, len(config.AllowedCallers))
	for caller := range config.AllowedCallers {
		if _, err := identity.NewWorkloadIdentity(caller); err != nil {
			return nil, errors.New("invalid strict transaction middleware configuration")
		}
		callers[caller] = struct{}{}
	}
	return &StrictTxnMiddleware{config: config, callers: callers}, nil
}

func (m *StrictTxnMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := transaction.ExtractTxnToken(r.Header, m.config.MaximumTokenBytes)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := m.config.Verifier.Verify(r.Context(), raw)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		caller, err := immediateCallerSPIFFEID(r.TLS, m.config.SPIFFEMTLSAlreadyVerified)
		if _, allowed := m.callers[caller]; err != nil || !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		route := SignedRoute{Target: claims.TransactionContext.WAI.Target, Tool: claims.TransactionContext.WAI.Tool}
		user, e1 := identity.NewUserIdentity(claims.Subject)
		agent, e2 := identity.NewAgentIdentity(claims.TransactionContext.WAI.Agent.ID, claims.TransactionContext.WAI.Agent.InstanceID)
		workload, e3 := identity.NewWorkloadIdentity(claims.RequestingWorkloadID)
		immediate, e4 := identity.NewWorkloadIdentity(caller)
		txn, e5 := identity.NewTransactionIdentity(claims.TransactionID, route.Target+":"+route.Tool)
		authorization, e6 := identity.NewAuthorizationContext(claims.Scope)
		if errors.Join(e1, e2, e3, e4, e5, e6) != nil || route.Target == "" || route.Tool == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		value, err := identity.NewRequestIdentityContext(user, agent, workload, immediate, txn, authorization)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		evidence, err := audit.NewVerifiedTxnTokenEvidence(raw, claims)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if m.config.Audit != nil {
			err = m.config.Audit.Write(audit.Event{
				Type: audit.TransactionVerifySucceeded, TransactionID: claims.TransactionID,
				UserID: claims.Subject, AgentID: claims.TransactionContext.WAI.Agent.ID,
				TransactionWorkloadID: claims.RequestingWorkloadID, ImmediateCallerSPIFFEID: caller,
				Target: m.config.Service, Tool: route.Tool, Purpose: route.Target + ":" + route.Tool,
				Decision: "allow", ReasonCode: "strict_txn_token_verified", ProtocolMethod: r.Method, Token: evidence,
			})
			if err != nil {
				http.Error(w, "audit unavailable", http.StatusInternalServerError)
				return
			}
		}
		ctx := identity.WithContext(r.Context(), value)
		ctx = context.WithValue(ctx, verifiedTokenContextKey{}, raw)
		ctx = context.WithValue(ctx, verifiedTokenEvidenceContextKey{}, evidence)
		ctx = context.WithValue(ctx, signedRouteContextKey{}, route)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
