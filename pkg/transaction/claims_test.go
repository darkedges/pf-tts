package transaction

import (
	"errors"
	"testing"
	"time"
)

func validClaims(now time.Time) Claims {
	return Claims{Issuer: "https://pf.example", Subject: "user", Audience: []string{"mcp"}, JWTID: "jti", AgentID: "urn:agent:demo", WorkloadID: "spiffe://example.org/agent/demo", TransactionID: "tx", Purpose: "customer.read", IssuedAt: now, ExpiresAt: now.Add(20 * time.Second)}
}

func TestClaimsRejectMissingAndInvalidTimeClaims(t *testing.T) {
	now := time.Now()
	tests := []Claims{{}, func() Claims { c := validClaims(now); c.AgentID = ""; return c }(), func() Claims { c := validClaims(now); c.ExpiresAt = now.Add(-time.Minute); return c }(), func() Claims { c := validClaims(now); c.IssuedAt = now.Add(time.Minute); return c }()}
	for _, claims := range tests {
		if err := claims.Validate(now, time.Second); !errors.Is(err, ErrInvalidClaims) {
			t.Fatalf("expected invalid claims, got %v", err)
		}
	}
}
