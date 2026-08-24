package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/transaction"
)

var tokenFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// TokenEvidence is a non-replayable summary of a transaction JWT that has
// already passed cryptographic and claim validation. Raw compact tokens are
// intentionally not representable here.
type TokenEvidence struct {
	Kind            string    `json:"kind"`
	Fingerprint     string    `json:"fingerprint"`
	Issuer          string    `json:"issuer"`
	Audience        []string  `json:"audience"`
	Scope           []string  `json:"scope"`
	JWTID           string    `json:"jwt_id"`
	AgentInstanceID string    `json:"agent_instance_id,omitempty"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func NewVerifiedTransactionTokenEvidence(raw string, claims transaction.Claims) (*TokenEvidence, error) {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(claims.Issuer) == "" || len(claims.Audience) == 0 || strings.TrimSpace(claims.JWTID) == "" || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return nil, errors.New("invalid verified transaction token evidence")
	}
	digest := sha256.Sum256([]byte(raw))
	evidence := &TokenEvidence{
		Kind: "transaction_jwt", Fingerprint: "sha256:" + hex.EncodeToString(digest[:]), Issuer: claims.Issuer,
		Audience: append([]string(nil), claims.Audience...), Scope: append([]string(nil), claims.Scope...), JWTID: claims.JWTID,
		AgentInstanceID: claims.AgentInstanceID, IssuedAt: claims.IssuedAt.UTC(), ExpiresAt: claims.ExpiresAt.UTC(),
	}
	if validateTokenEvidence(evidence, 64<<10) != nil {
		return nil, errors.New("invalid verified transaction token evidence")
	}
	return evidence, nil
}

func NewVerifiedTxnTokenEvidence(raw string, claims transaction.TxnTokenClaims) (*TokenEvidence, error) {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(claims.Issuer) == "" || strings.TrimSpace(claims.Audience) == "" || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return nil, errors.New("invalid verified transaction token evidence")
	}
	digest := sha256.Sum256([]byte(raw))
	evidence := &TokenEvidence{
		Kind: "txn_token", Fingerprint: "sha256:" + hex.EncodeToString(digest[:]), Issuer: claims.Issuer,
		Audience: []string{claims.Audience}, Scope: append([]string(nil), claims.Scope...), JWTID: claims.JWTID,
		AgentInstanceID: claims.TransactionContext.WAI.Agent.InstanceID, IssuedAt: claims.IssuedAt.UTC(), ExpiresAt: claims.ExpiresAt.UTC(),
	}
	if validateTokenEvidence(evidence, 64<<10) != nil {
		return nil, errors.New("invalid verified transaction token evidence")
	}
	return evidence, nil
}

func validateTokenEvidence(evidence *TokenEvidence, maximumFieldBytes int) error {
	if evidence == nil {
		return nil
	}
	if (evidence.Kind != "transaction_jwt" && evidence.Kind != "txn_token") || !tokenFingerprintPattern.MatchString(evidence.Fingerprint) || strings.TrimSpace(evidence.Issuer) == "" || len(evidence.Audience) == 0 || (evidence.Kind == "transaction_jwt" && strings.TrimSpace(evidence.JWTID) == "") || evidence.IssuedAt.IsZero() || evidence.ExpiresAt.IsZero() || !evidence.ExpiresAt.After(evidence.IssuedAt) {
		return ErrInvalidRecord
	}
	fields := []string{evidence.Kind, evidence.Fingerprint, evidence.Issuer, evidence.AgentInstanceID}
	if evidence.JWTID != "" {
		fields = append(fields, evidence.JWTID)
	}
	fields = append(fields, evidence.Audience...)
	fields = append(fields, evidence.Scope...)
	for _, value := range fields {
		if strings.TrimSpace(value) == "" || len(value) > maximumFieldBytes || credentialShaped(value) {
			return ErrInvalidRecord
		}
	}
	return nil
}

func cloneTokenEvidence(evidence *TokenEvidence) *TokenEvidence {
	if evidence == nil {
		return nil
	}
	copy := *evidence
	copy.Audience = append([]string(nil), evidence.Audience...)
	copy.Scope = append([]string(nil), evidence.Scope...)
	return &copy
}
