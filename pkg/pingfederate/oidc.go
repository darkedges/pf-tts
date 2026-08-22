package pingfederate

import (
	"context"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
)

type oidcClaims struct {
	jwt.Claims
	Nonce string `json:"nonce"`
	AZP   string `json:"azp"`
}

// VerifyIDToken verifies an ID token using the verifier's pinned issuer, keys,
// algorithms, and clock policy. clientID and nonce are server-side values.
func (v *JWTVerifier) VerifyIDToken(ctx context.Context, rawToken, clientID, nonce string) (string, error) {
	if strings.TrimSpace(rawToken) == "" || strings.TrimSpace(clientID) == "" || strings.TrimSpace(nonce) == "" {
		return "", verificationError("ID token, client ID, and nonce are required")
	}
	token, err := jwt.ParseSigned(rawToken, v.config.Algorithms)
	if err != nil {
		return "", verificationError("ID token parse failed")
	}
	if len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return "", verificationError("missing or ambiguous key ID")
	}
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return "", err
	}
	matches := keys.Key(token.Headers[0].KeyID)
	if len(matches) != 1 {
		return "", verificationError("unknown or ambiguous key ID")
	}
	var claims oidcClaims
	if err := token.Claims(matches[0].Key, &claims); err != nil {
		return "", verificationError("ID token signature validation failed")
	}
	now := v.config.Now()
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.config.Issuer, AnyAudience: jwt.Audience{clientID}, Time: now}, v.config.ClockSkew); err != nil {
		return "", verificationError("ID token standard claim validation failed")
	}
	if claims.Subject == "" || claims.Expiry == nil || claims.IssuedAt == nil || claims.Nonce != nonce {
		return "", verificationError("ID token required claim validation failed")
	}
	if claims.IssuedAt.Time().After(now.Add(v.config.ClockSkew)) {
		return "", verificationError("ID token issued-at time is in the future")
	}
	// OIDC requires azp when multiple audiences are present. Reject ambiguity
	// unless the authorized party is exactly this client.
	if len(claims.Audience) > 1 && claims.AZP != clientID {
		return "", verificationError("ID token audience is ambiguous")
	}
	return claims.Subject, nil
}
