package transaction

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidClaims = errors.New("invalid transaction claims")

type Claims struct {
	Issuer          string
	Subject         string
	Audience        []string
	JWTID           string
	AgentID         string
	AgentInstanceID string
	WorkloadID      string
	TransactionID   string
	Purpose         string
	Scope           []string
	IssuedAt        time.Time
	NotBefore       time.Time
	ExpiresAt       time.Time
}

type Verifier interface {
	Verify(ctx context.Context, rawToken string, requiredAudience string) (Claims, error)
}

func (c Claims) Validate(now time.Time, clockSkew time.Duration) error {
	if strings.TrimSpace(c.Issuer) == "" || strings.TrimSpace(c.Subject) == "" || len(c.Audience) == 0 || strings.TrimSpace(c.JWTID) == "" || strings.TrimSpace(c.AgentID) == "" || strings.TrimSpace(c.WorkloadID) == "" || strings.TrimSpace(c.TransactionID) == "" || strings.TrimSpace(c.Purpose) == "" || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: required identity or standard claim is missing", ErrInvalidClaims)
	}
	for _, audience := range c.Audience {
		if strings.TrimSpace(audience) == "" {
			return fmt.Errorf("%w: empty audience", ErrInvalidClaims)
		}
	}
	if c.ExpiresAt.Before(now.Add(-clockSkew)) {
		return fmt.Errorf("%w: token expired", ErrInvalidClaims)
	}
	if !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: token not yet valid", ErrInvalidClaims)
	}
	if c.IssuedAt.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: issued-at is in the future", ErrInvalidClaims)
	}
	return nil
}
