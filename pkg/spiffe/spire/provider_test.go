package spire

import (
	"context"
	"errors"
	"testing"

	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type fakeClient struct{ closes int }

func (*fakeClient) FetchJWTSVIDs(context.Context, jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	return nil, errors.New("not implemented")
}
func (*fakeClient) FetchX509SVIDs(context.Context) ([]*x509svid.SVID, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeClient) Close() error { f.closes++; return nil }

type fakeRotatingSource struct {
	id     spiffeid.ID
	closes int
}

func (f *fakeRotatingSource) GetX509SVID() (*x509svid.SVID, error) {
	return &x509svid.SVID{ID: f.id}, nil
}
func (*fakeRotatingSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, errors.New("not needed by this test")
}
func (f *fakeRotatingSource) Close() error { f.closes++; return nil }

type denyPolicy struct{}

func (denyPolicy) AuthorizeSPIFFEID(string) bool { return false }

func TestSelectExpectedJWTSVIDFailsClosed(t *testing.T) {
	expected := spiffeid.RequireFromString("spiffe://example.org/agent/demo")
	other := spiffeid.RequireFromString("spiffe://example.org/agent/other")
	tests := []struct {
		name  string
		svids []*jwtsvid.SVID
	}{
		{"zero", nil},
		{"multiple", []*jwtsvid.SVID{{ID: expected}, {ID: expected}}},
		{"unexpected", []*jwtsvid.SVID{{ID: other}}},
		{"nil candidate", []*jwtsvid.SVID{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := selectExpectedJWT(tt.svids, expected); !errors.Is(err, ErrIdentitySelection) {
				t.Fatalf("expected identity-selection error, got %v", err)
			}
		})
	}
}

func TestSelectExpectedX509SVIDFailsClosed(t *testing.T) {
	expected := spiffeid.RequireFromString("spiffe://example.org/agent/demo")
	other := spiffeid.RequireFromString("spiffe://example.org/agent/other")
	tests := []struct {
		name  string
		svids []*x509svid.SVID
	}{
		{"zero", nil},
		{"multiple", []*x509svid.SVID{{ID: expected}, {ID: expected}}},
		{"unexpected", []*x509svid.SVID{{ID: other}}},
		{"nil candidate", []*x509svid.SVID{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := selectExpectedX509(tt.svids, expected); !errors.Is(err, ErrIdentitySelection) {
				t.Fatalf("expected identity-selection error, got %v", err)
			}
		})
	}
}

func TestSelectExpectedIdentitySucceeds(t *testing.T) {
	expected := spiffeid.RequireFromString("spiffe://example.org/agent/demo")
	jwt := &jwtsvid.SVID{ID: expected}
	if got, err := selectExpectedJWT([]*jwtsvid.SVID{jwt}, expected); err != nil || got != jwt {
		t.Fatalf("JWT selection failed: %v", err)
	}
	x509 := &x509svid.SVID{ID: expected}
	if got, err := selectExpectedX509([]*x509svid.SVID{x509}, expected); err != nil || got != x509 {
		t.Fatalf("X.509 selection failed: %v", err)
	}
}

func TestValidateAudiencesRejectsAmbiguity(t *testing.T) {
	for _, audiences := range [][]string{nil, {""}, {"aud", "aud"}} {
		if _, err := validateAudiences(audiences); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected invalid audience error, got %v", err)
		}
	}
}

func TestNewRejectsInvalidOptionsBeforeDial(t *testing.T) {
	tests := []Options{
		{},
		{Endpoint: "not-a-workload-api-address", ExpectedSPIFFEID: "spiffe://example.org/agent/demo"},
		{Endpoint: "unix:///run/spire/sockets/agent.sock", ExpectedSPIFFEID: "caller-supplied-agent"},
	}
	for _, options := range tests {
		if _, err := New(context.Background(), options); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected invalid options error, got %v", err)
		}
	}
}

func TestX509SourceRequiresExplicitPeerPolicy(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/agent/demo")
	owner := &Provider{expected: id, client: &fakeClient{}, x509: &fakeRotatingSource{id: id}}
	source, err := owner.X509Source(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.TLSConfig(context.Background(), nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected explicit-policy error, got %v", err)
	}
	config, err := source.TLSConfig(context.Background(), denyPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		t.Fatal("expected mTLS client configuration")
	}
}

func TestX509SourceCloseClosesOwnedResourcesOnce(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/agent/demo")
	client := &fakeClient{}
	rotation := &fakeRotatingSource{id: id}
	owner := &Provider{expected: id, client: client, x509: rotation}
	source := &x509Source{source: rotation, owner: owner}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if client.closes != 1 || rotation.closes != 1 {
		t.Fatalf("resources closed client=%d source=%d; want one each", client.closes, rotation.closes)
	}
}

var _ corespiffe.Provider = (*Provider)(nil)
