package tests

import (
	"os"
	"strings"
	"testing"
)

func TestTransactionTokensConformanceEvidenceIsQualified(t *testing.T) {
	data, err := os.ReadFile("../docs/transaction-tokens-conformance.md")
	if err != nil {
		t.Fatal(err)
	}
	report := strings.Join(strings.Fields(string(data)), " ")
	for _, required := range []string{
		"draft-ietf-oauth-transaction-tokens-11",
		"draft-oauth-transaction-tokens-for-agents-06",
		"exactly one `Txn-Token`",
		"exact SPIFFE X.509-SVID mTLS",
		"non-signing TTS adapter",
		"not an IETF conformance certification",
		"not native PingFederate support",
		"not implemented",
	} {
		if !strings.Contains(report, required) {
			t.Fatalf("conformance evidence omits required qualification %q", required)
		}
	}
	for _, forbidden := range []string{
		"fully conformant", "IETF certified", "PingFederate natively supports Transaction Tokens",
	} {
		if strings.Contains(report, forbidden) {
			t.Fatalf("conformance evidence contains unsupported claim %q", forbidden)
		}
	}
}
