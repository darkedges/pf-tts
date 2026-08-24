package mcp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/middleware"
	"example.com/workload-agent-identity/pkg/transaction"
)

var ErrStrictTransactionDenied = errors.New("strict transaction request denied")

type SignedRouteAuthorizer struct {
	inner Authorizer
}

func NewSignedRouteAuthorizer(inner Authorizer) (*SignedRouteAuthorizer, error) {
	if inner == nil {
		return nil, ErrStrictTransactionDenied
	}
	return &SignedRouteAuthorizer{inner: inner}, nil
}

func (a *SignedRouteAuthorizer) Authorize(ctx context.Context, value identity.RequestIdentityContext, target, tool string) error {
	if err := ctx.Err(); err != nil {
		return ErrStrictTransactionDenied
	}
	route, ok := middleware.VerifiedSignedRoute(ctx)
	if !ok || strings.TrimSpace(target) == "" || strings.TrimSpace(tool) == "" || route.Target != target || route.Tool != tool {
		return ErrStrictTransactionDenied
	}
	if err := a.inner.Authorize(ctx, value, target, tool); err != nil {
		return ErrStrictTransactionDenied
	}
	return nil
}

func PropagateVerifiedTxnToken(ctx context.Context, request *http.Request, maximumBytes int) error {
	if request == nil || request.Header == nil || maximumBytes <= 0 {
		return ErrStrictTransactionDenied
	}
	if _, ok := middleware.VerifiedSignedRoute(ctx); !ok {
		return ErrStrictTransactionDenied
	}
	raw, ok := middleware.VerifiedTransactionToken(ctx)
	if !ok {
		return ErrStrictTransactionDenied
	}
	before := request.Header.Clone()
	if err := transaction.SetTxnToken(request.Header, raw, maximumBytes); err != nil {
		request.Header = before
		return ErrStrictTransactionDenied
	}
	return nil
}
