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

	"example.com/workload-agent-identity/pkg/audit"
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

// StrictWorkloadAgentBindings is the reviewed workload-to-AgentID map for the
// strict call chain. Every strict hop verifies against the same set, so a
// transaction the gateway accepts cannot be rejected further down the chain by
// a hop that was updated separately. Entries are exact: a workload can never
// assert a different AgentID, and this map is never widened to a wildcard.
func StrictWorkloadAgentBindings() map[string]string {
	return map[string]string{
		"spiffe://example.org/agent/demo":    "urn:agent:demo",
		"spiffe://example.org/agent/web-app": "urn:agent:web-app",
	}
}

func StrictTxnVerifier() (*transaction.TxnTokenVerifier, error) {
	return StrictTxnVerifierForBindings(StrictWorkloadAgentBindings())
}

func StrictTxnVerifierForBindings(bindings map[string]string) (*transaction.TxnTokenVerifier, error) {
	if len(bindings) == 0 {
		return nil, errors.New("strict workload-agent bindings are required")
	}
	issuer, err := Required("PF_TRANSACTION_ISSUER")
	if err != nil {
		return nil, err
	}
	jwksURL, err := Required("PF_JWKS_URL")
	if err != nil {
		return nil, err
	}
	client, err := PFHTTPClient()
	if err != nil {
		return nil, err
	}
	keys, err := pingfederate.NewJWKSKeyResolver(jwksURL, client, 1<<20)
	if err != nil {
		return nil, err
	}
	return transaction.NewTxnTokenVerifier(transaction.TxnTokenVerifierConfig{
		Mode: transaction.ProfileTxnTokenV11, Issuer: issuer, TrustDomain: "example.org",
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: 5 * time.Second,
		MaximumLifetime: 60 * time.Second, MaximumTokenBytes: 16 << 10, MaximumPayloadBytes: 8 << 10,
		MaximumIdentifierBytes: 256, MaximumContextBytes: 2 << 10, MaximumScopes: 1,
		AllowedScopes:         map[string]struct{}{"mcp.system.whoami": {}},
		WorkloadAgentBindings: bindings, Keys: keys,
	})
}

// PFHTTPClient creates the bounded HTTPS client used for every backchannel call
// to PingFederate: the token exchange, the authorization code exchange, and JWKS
// retrieval.
//
// When PF_CA_FILE is configured, it is the ONLY trust anchor. Adding it to the
// system pool instead would mean any public certificate authority could satisfy
// this client, so a caller pointed at a public address would happily complete the
// RFC 8693 exchange against whatever terminated that TLS -- carrying the user's
// access token and the agent's JWT-SVID. Pinning makes reaching PingFederate
// through an edge a connection failure rather than a silent disclosure.
//
// The system pool is used only when no PF_CA_FILE is configured, which is the
// case for deployments fronted by a publicly trusted certificate.
func PFHTTPClient() (*http.Client, error) {
	caFile := strings.TrimSpace(os.Getenv("PF_CA_FILE"))
	var pool *x509.CertPool
	if caFile == "" {
		system, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		pool = system
	} else {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read PF_CA_FILE: %w", err)
		}
		pool = x509.NewCertPool()
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

// CAHTTPClient creates a bounded HTTPS client whose ONLY trust anchor is the
// configured PEM. It is used to reach external product adapters, such as the
// PingAuthorize decision point, over their own certificates.
//
// The configured anchor replaces the system pool rather than being added to it.
// Appending would mean any public certificate authority could also satisfy this
// client, so a workload pointed at a public address would happily send its
// authorization request -- carrying the user, agent, workload, and transaction
// identifiers -- to whatever terminated that TLS. Pinning makes that a
// connection failure instead of a silent disclosure.
//
// This mirrors PFHTTPClient, which was corrected for the same reason.
func CAHTTPClient(caEnvironmentVariable string, timeout time.Duration) (*http.Client, error) {
	if strings.TrimSpace(caEnvironmentVariable) == "" || timeout <= 0 {
		return nil, errors.New("CA environment variable and positive timeout are required")
	}
	caFile, err := Required(caEnvironmentVariable)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caEnvironmentVariable, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no valid PEM certificates", caEnvironmentVariable)
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}, nil
}

func Middleware(audience string, verifier *pingfederate.JWTVerifier, allowedCaller, target string, sinks ...audit.Sink) (middleware.Middleware, error) {
	return MiddlewareForCallers(audience, verifier, []string{allowedCaller}, target, sinks...)
}

func MiddlewareForCallers(audience string, verifier *pingfederate.JWTVerifier, allowedCallers []string, target string, sinks ...audit.Sink) (middleware.Middleware, error) {
	policy, err := corespiffe.NewExactPeerPolicy(allowedCallers...)
	if err != nil {
		return middleware.Middleware{}, err
	}
	if strings.TrimSpace(target) == "" {
		return middleware.Middleware{}, errors.New("audit target is required")
	}
	sink := audit.Sink(audit.NewJSONSink(os.Stdout))
	if len(sinks) > 1 || len(sinks) == 1 && sinks[0] == nil {
		return middleware.Middleware{}, errors.New("at most one non-nil audit sink is allowed")
	}
	if len(sinks) == 1 {
		sink = sinks[0]
	}
	return middleware.Middleware{
		Verifier: verifier, Audience: audience, Callers: exactCaller{policy}, SPIFFEMTLSAlreadyVerified: true,
		Audit: sink, Target: target,
	}, nil
}

func AuditSink(ctx context.Context, source corespiffe.X509Source) (audit.Sink, error) {
	stdout := audit.NewJSONSink(os.Stdout)
	endpoint := strings.TrimSpace(os.Getenv("AUDIT_COLLECTOR_URL"))
	if endpoint == "" {
		return stdout, nil
	}
	remote, err := AuditRemote(ctx, source)
	if err != nil {
		return nil, err
	}
	return audit.NewFanout(stdout, remote)
}

func AuditRemote(ctx context.Context, source corespiffe.X509Source) (*audit.Remote, error) {
	endpoint, err := Required("AUDIT_COLLECTOR_URL")
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("AUDIT_COLLECTOR_URL must be an HTTPS URL without query or fragment")
	}
	peer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/audit/collector")
	if err != nil {
		return nil, err
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 5*time.Second)
	if err != nil {
		return nil, err
	}
	remote, err := audit.NewRemote(parsed.String(), client, 8<<20)
	if err != nil {
		return nil, err
	}
	return remote, nil
}

type exactCaller struct{ policy corespiffe.ExactPeerPolicy }

func (p exactCaller) Authorize(_ transaction.Claims, caller string) error {
	if !p.policy.AuthorizeSPIFFEID(caller) {
		return errors.New("caller SPIFFE ID denied")
	}
	return nil
}
