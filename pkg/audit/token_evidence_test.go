package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"example.com/workload-agent-identity/pkg/transaction"
)

func verifiedEvidenceClaims() transaction.Claims {
	now := time.Now().UTC().Truncate(time.Second)
	return transaction.Claims{
		Issuer: "https://issuer.example", Audience: []string{"mcp-gateway"}, Scope: []string{"mcp:invoke"}, JWTID: "jti-123",
		AgentInstanceID: "instance-123", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
}

func TestVerifiedTokenEvidenceProvesSamenessWithoutExposingBearer(t *testing.T) {
	const raw = "raw.header.payload.signature.secret"
	first, err := NewVerifiedTransactionTokenEvidence(raw, verifiedEvidenceClaims())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewVerifiedTransactionTokenEvidence(raw, verifiedEvidenceClaims())
	changed, _ := NewVerifiedTransactionTokenEvidence(raw+"-changed", verifiedEvidenceClaims())
	if first.Fingerprint != second.Fingerprint || first.Fingerprint == changed.Fingerprint || !tokenFingerprintPattern.MatchString(first.Fingerprint) {
		t.Fatal("transaction token fingerprint is not stable and collision-resistant across hops")
	}
	encoded, _ := json.Marshal(Event{Type: TransactionVerifySucceeded, Token: first})
	if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), "payload.signature") {
		t.Fatal("raw transaction bearer token leaked into audit evidence")
	}
}

func TestTokenEvidenceRejectsPartialCredentialShapedOrMutableInput(t *testing.T) {
	store, _ := NewStore(StoreConfig{MaximumRecords: 2, MaximumFieldBytes: 256, Retention: time.Minute})
	claims := verifiedEvidenceClaims()
	evidence, _ := NewVerifiedTransactionTokenEvidence("verified-token", claims)
	record := validRecord("evidence", "user")
	record.Token = evidence
	if _, err := store.Add(record); err != nil {
		t.Fatal(err)
	}
	evidence.Audience[0] = "attacker-mutated"
	stored, err := store.GetByUser("user", "evidence")
	if err != nil || stored.Token.Audience[0] != "mcp-gateway" {
		t.Fatal("caller mutated stored verified token evidence")
	}

	unsafe := validRecord("unsafe", "user")
	unsafe.Token = &TokenEvidence{Kind: "transaction_jwt", Fingerprint: "header.payload.signature", Issuer: "Bearer stolen"}
	if _, err := store.Add(unsafe); err == nil {
		t.Fatal("partial or credential-shaped token evidence accepted")
	}
}

func TestVerifiedStrictTxnTokenEvidenceAllowsOptionalJWTIDWithoutRawToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	claims := transaction.TxnTokenClaims{
		Issuer: "https://issuer.example", Audience: "example.org", Scope: []string{"mcp.system.whoami"},
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
		TransactionContext: transaction.TransactionContext{WAI: transaction.WAITransactionContext{Agent: transaction.WAIAgentContext{InstanceID: "instance"}}},
	}
	const raw = "header.payload.signature"
	evidence, err := NewVerifiedTxnTokenEvidence(raw, claims)
	if err != nil || evidence.Kind != "txn_token" || evidence.JWTID != "" || !tokenFingerprintPattern.MatchString(evidence.Fingerprint) {
		t.Fatalf("strict evidence mismatch: evidence=%+v err=%v", evidence, err)
	}
	encoded, _ := json.Marshal(evidence)
	if strings.Contains(string(encoded), raw) {
		t.Fatal("raw strict Transaction Token leaked into evidence")
	}
	claims.ExpiresAt = claims.IssuedAt
	if _, err := NewVerifiedTxnTokenEvidence(raw, claims); err == nil {
		t.Fatal("invalid strict token evidence accepted")
	}
}
