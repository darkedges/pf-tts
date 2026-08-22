package spiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"testing"
)

type fakeProvider struct {
	id        string
	audiences []string
	closed    bool
	source    *fakeX509Source
}

func (f *fakeProvider) FetchJWTSVID(_ context.Context, audiences []string) (JWTSVID, error) {
	if len(audiences) == 0 {
		return JWTSVID{}, errors.New("audience required")
	}
	f.audiences = append([]string(nil), audiences...)
	return JWTSVID{Token: "opaque-test-token", SPIFFEID: f.id}, nil
}
func (f *fakeProvider) X509Source(context.Context) (X509Source, error) { return f.source, nil }
func (f *fakeProvider) SPIFFEID() string                               { return f.id }
func (f *fakeProvider) Close() error                                   { f.closed = true; return nil }

type fakeX509Source struct{ closed bool }

func (f *fakeX509Source) TLSConfig(context.Context, PeerPolicy) (*tls.Config, error) {
	return &tls.Config{MinVersion: tls.VersionTLS13}, nil
}
func (f *fakeX509Source) ServerTLSConfig(context.Context, PeerPolicy) (*tls.Config, error) {
	return &tls.Config{MinVersion: tls.VersionTLS13}, nil
}
func (f *fakeX509Source) Close() error { f.closed = true; return nil }

func TestProviderBoundaryWithFake(t *testing.T) {
	f := &fakeProvider{id: "spiffe://example.org/agent/demo", source: &fakeX509Source{}}
	svid, err := f.FetchJWTSVID(context.Background(), []string{"aud-one", "aud-two"})
	if err != nil {
		t.Fatal(err)
	}
	if svid.SPIFFEID != f.SPIFFEID() {
		t.Fatal("selected SPIFFE ID differs from issued identity")
	}
	if !reflect.DeepEqual(f.audiences, []string{"aud-one", "aud-two"}) {
		t.Fatal("audiences were not passed intact")
	}
	source, err := f.X509Source(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.TLSConfig(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.closed || !f.source.closed {
		t.Fatal("identity resources were not closed")
	}
}

func TestProviderRejectsMissingJWTAudience(t *testing.T) {
	f := &fakeProvider{id: "spiffe://example.org/agent/demo"}
	if _, err := f.FetchJWTSVID(context.Background(), nil); err == nil {
		t.Fatal("expected missing audience to fail")
	}
}
