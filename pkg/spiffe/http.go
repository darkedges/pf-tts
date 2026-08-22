package spiffe

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func NewHTTPClient(ctx context.Context, source X509Source, policy PeerPolicy, timeout time.Duration) (*http.Client, error) {
	if source == nil || policy == nil || timeout <= 0 {
		return nil, fmt.Errorf("invalid SPIFFE HTTP client configuration")
	}
	config, err := source.TLSConfig(ctx, policy)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: config}}, nil
}

func ConfigureHTTPServer(ctx context.Context, server *http.Server, source X509Source, policy PeerPolicy) error {
	if server == nil || source == nil || policy == nil {
		return fmt.Errorf("invalid SPIFFE HTTP server configuration")
	}
	config, err := source.ServerTLSConfig(ctx, policy)
	if err != nil {
		return err
	}
	server.TLSConfig = config
	return nil
}
