package spiffe

import (
	"context"
	"crypto/tls"
)

type JWTSVID struct {
	Token    string
	SPIFFEID string
}

type Provider interface {
	FetchJWTSVID(ctx context.Context, audiences []string) (JWTSVID, error)
	X509Source(ctx context.Context) (X509Source, error)
	SPIFFEID() string
	Close() error
}

type X509Source interface {
	TLSConfig(ctx context.Context, policy PeerPolicy) (*tls.Config, error)
	ServerTLSConfig(ctx context.Context, policy PeerPolicy) (*tls.Config, error)
	Close() error
}

type PeerPolicy interface {
	AuthorizeSPIFFEID(spiffeID string) bool
}
