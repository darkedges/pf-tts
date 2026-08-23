package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestJSONSinkCannotLogCredentials(t *testing.T) {
	var out bytes.Buffer
	s := NewJSONSink(&out)
	if err := s.Write(Event{Type: MCPToolDenied, TransactionID: "tx", ReasonCode: "policy_denied"}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Bearer ", "access_token", "client_secret", "private_key"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("audit output contains credential field %q", secret)
		}
	}
	before := out.String()
	if err := s.Write(Event{Type: MCPToolDenied, UserID: "Bearer stolen-token"}); err == nil {
		t.Fatal("credential-shaped audit value accepted")
	}
	if out.String() != before {
		t.Fatal("rejected credential-shaped value was written to stdout")
	}
}
