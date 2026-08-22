package spiffe

import (
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type ExactPeerPolicy struct{ allowed map[string]struct{} }

func NewExactPeerPolicy(ids ...string) (ExactPeerPolicy, error) {
	p := ExactPeerPolicy{allowed: make(map[string]struct{}, len(ids))}
	if len(ids) == 0 {
		return ExactPeerPolicy{}, ErrInvalidIdentityPolicy
	}
	for _, raw := range ids {
		id, err := spiffeid.FromString(strings.TrimSpace(raw))
		if err != nil {
			return ExactPeerPolicy{}, ErrInvalidIdentityPolicy
		}
		p.allowed[id.String()] = struct{}{}
	}
	return p, nil
}
func (p ExactPeerPolicy) AuthorizeSPIFFEID(id string) bool { _, ok := p.allowed[id]; return ok }

var ErrInvalidIdentityPolicy = &policyError{}

type policyError struct{}

func (*policyError) Error() string { return "invalid SPIFFE identity policy" }
