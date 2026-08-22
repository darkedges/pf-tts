package agent

import (
	"context"
	"testing"
)

func TestAttackModesFailBeforeCredentialUse(t *testing.T) {
	r := Runner{}
	for _, mode := range []Mode{SpoofAgent, ExpiredToken} {
		if err := r.Run(context.Background(), "user-secret", "customer.read", mode); err == nil {
			t.Fatalf("mode %s did not fail", mode)
		}
	}
}
func TestRequiredInput(t *testing.T) {
	if err := (Runner{}).Run(context.Background(), "", "customer.read", Normal); err == nil {
		t.Fatal("missing user token accepted")
	}
}
