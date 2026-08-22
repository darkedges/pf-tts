package demoenv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"example.com/workload-agent-identity/pkg/middleware"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	spiffeadapter "example.com/workload-agent-identity/pkg/spiffe/spire"
	"example.com/workload-agent-identity/pkg/transaction"
	"github.com/go-jose/go-jose/v4"
)

func Required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func URL(name string) (*url.URL, error) {
	raw, err := Required(name)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("%s must be an HTTPS URL without a query", name)
	}
	return parsed, nil
}

func Provider(ctx context.Context, expectedID string) (*spiffeadapter.Provider, corespiffe.X509Source, error) {
	endpoint, err := Required("SPIFFE_ENDPOINT")
	if err != nil {
		return nil, nil, err
	}
	provider, err := spiffeadapter.New(ctx, spiffeadapter.Options{Endpoint: endpoint, ExpectedSPIFFEID: expectedID})
	if err != nil {
		return nil, nil, err
	}
	source, err := provider.X509Source(ctx)
	if err != nil {
		_ = provider.Close()
		return nil, nil, err
	}
	return provider, source, nil
}

func Verifier() (*pingfederate.JWTVerifier, error) {
	issuer, err := Required("PF_TRANSACTION_ISSUER")
	if err != nil {
		return nil, err
	}
	jwks, err := Required("PF_JWKS_URL")
	if err != nil {
		return nil, err
	}
	httpClient, err := PFHTTPClient()
	if err != nil {
		return nil, err
	}
	return pingfederate.NewJWTVerifier(pingfederate.VerifierConfig{
		Issuer: issuer, JWKSURL: jwks, Algorithms: []jose.SignatureAlgorithm{jose.RS256},
		ClockSkew: 5 * time.Second, HTTPClient: httpClient,
	})
}

func PFHTTPClient() (*http.Client, error) {
	caFile := strings.TrimSpace(os.Getenv("PF_CA_FILE"))
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", err)
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read PF_CA_FILE: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("PF_CA_FILE contains no valid PEM certificates")
		}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}},
	}, nil
}

func Middleware(audience string, verifier *pingfederate.JWTVerifier, allowedCaller string) (middleware.Middleware, error) {
	policy, err := corespiffe.NewExactPeerPolicy(allowedCaller)
	if err != nil {
		return middleware.Middleware{}, err
	}
	return middleware.Middleware{Verifier: verifier, Audience: audience, Callers: exactCaller{policy}, SPIFFEMTLSAlreadyVerified: true}, nil
}

type exactCaller struct{ policy corespiffe.ExactPeerPolicy }

func (p exactCaller) Authorize(_ transaction.Claims, caller string) error {
	if !p.policy.AuthorizeSPIFFEID(caller) {
		return errors.New("caller SPIFFE ID denied")
	}
	return nil
}
