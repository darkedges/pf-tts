package transaction

import (
	"errors"
	"testing"
)

func TestProfileModeRequiresExplicitKnownMode(t *testing.T) {
	for _, mode := range []ProfileMode{"", "auto", "txn-token", "legacy"} {
		if err := mode.Validate(); !errors.Is(err, ErrInvalidProfileMode) {
			t.Fatalf("mode %q: expected ErrInvalidProfileMode, got %v", mode, err)
		}
	}
	for _, mode := range []ProfileMode{ProfileLegacyWAIJWT, ProfileTxnTokenV11} {
		if err := mode.Validate(); err != nil {
			t.Fatalf("mode %q unexpectedly rejected: %v", mode, err)
		}
	}
}
