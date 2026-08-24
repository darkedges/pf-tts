package transaction

import (
	"errors"
	"fmt"
)

var ErrInvalidProfileMode = errors.New("invalid transaction token profile mode")

type ProfileMode string

const (
	ProfileLegacyWAIJWT ProfileMode = "legacy-wai-jwt"
	ProfileTxnTokenV11  ProfileMode = "ietf-txn-token-v11"
)

func (m ProfileMode) Validate() error {
	switch m {
	case ProfileLegacyWAIJWT, ProfileTxnTokenV11:
		return nil
	default:
		return fmt.Errorf("%w", ErrInvalidProfileMode)
	}
}
