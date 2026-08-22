package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"

	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	ErrInvalidOptions    = errors.New("invalid SPIFFE provider options")
	ErrIdentitySelection = errors.New("SPIFFE identity selection failed")
)

type Options struct {
	Endpoint         string
	ExpectedSPIFFEID string
}

type workloadClient interface {
	FetchJWTSVIDs(context.Context, jwtsvid.Params) ([]*jwtsvid.SVID, error)
	FetchX509SVIDs(context.Context) ([]*x509svid.SVID, error)
	Close() error
}

type rotatingX509Source interface {
	x509svid.Source
	x509bundle.Source
	Close() error
}

type Provider struct {
	expected spiffeid.ID
	client   workloadClient
	x509     rotatingX509Source
	once     sync.Once
	closeErr error
}

func New(ctx context.Context, options Options) (*Provider, error) {
	endpoint := strings.TrimSpace(options.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("%w: Workload API endpoint is required", ErrInvalidOptions)
	}
	if err := workloadapi.ValidateAddress(endpoint); err != nil {
		return nil, fmt.Errorf("%w: invalid Workload API endpoint: %v", ErrInvalidOptions, err)
	}
	expected, err := spiffeid.FromString(strings.TrimSpace(options.ExpectedSPIFFEID))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expected SPIFFE ID: %v", ErrInvalidOptions, err)
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(endpoint))
	if err != nil {
		return nil, fmt.Errorf("create Workload API client: %w", err)
	}
	if _, err := fetchExpectedX509(ctx, client, expected); err != nil {
		_ = client.Close()
		return nil, err
	}
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClient(client),
		workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			selected, _ := selectExpectedX509(svids, expected)
			return selected
		}),
	)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("create rotating X.509 source: %w", err)
	}
	return &Provider{expected: expected, client: client, x509: source}, nil
}

func (p *Provider) FetchJWTSVID(ctx context.Context, audiences []string) (corespiffe.JWTSVID, error) {
	clean, err := validateAudiences(audiences)
	if err != nil {
		return corespiffe.JWTSVID{}, err
	}
	svids, err := p.client.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: clean[0], ExtraAudiences: clean[1:]})
	if err != nil {
		return corespiffe.JWTSVID{}, fmt.Errorf("fetch JWT-SVIDs: %w", err)
	}
	selected, err := selectExpectedJWT(svids, p.expected)
	if err != nil {
		return corespiffe.JWTSVID{}, err
	}
	return corespiffe.JWTSVID{Token: selected.Marshal(), SPIFFEID: selected.ID.String()}, nil
}

func (p *Provider) X509Source(context.Context) (corespiffe.X509Source, error) {
	if _, err := p.x509.GetX509SVID(); err != nil {
		return nil, fmt.Errorf("get selected X.509-SVID: %w", err)
	}
	return &x509Source{source: p.x509, owner: p}, nil
}

func (p *Provider) SPIFFEID() string { return p.expected.String() }

func (p *Provider) Close() error {
	p.once.Do(func() { p.closeErr = errors.Join(p.x509.Close(), p.client.Close()) })
	return p.closeErr
}

type x509Source struct {
	source rotatingX509Source
	owner  *Provider
}

func (s *x509Source) TLSConfig(_ context.Context, policy corespiffe.PeerPolicy) (*tls.Config, error) {
	return s.tlsConfig(policy, false)
}

func (s *x509Source) ServerTLSConfig(_ context.Context, policy corespiffe.PeerPolicy) (*tls.Config, error) {
	return s.tlsConfig(policy, true)
}

func (s *x509Source) tlsConfig(policy corespiffe.PeerPolicy, server bool) (*tls.Config, error) {
	if policy == nil {
		return nil, fmt.Errorf("%w: peer policy is required", ErrInvalidOptions)
	}
	authorizer := func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		if !policy.AuthorizeSPIFFEID(id.String()) {
			return fmt.Errorf("peer SPIFFE ID is not authorized")
		}
		return nil
	}
	if server {
		return tlsconfig.MTLSServerConfig(s.source, s.source, authorizer), nil
	}
	return tlsconfig.MTLSClientConfig(s.source, s.source, authorizer), nil
}

func (s *x509Source) Close() error { return s.owner.Close() }

func fetchExpectedX509(ctx context.Context, client workloadClient, expected spiffeid.ID) (*x509svid.SVID, error) {
	svids, err := client.FetchX509SVIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch X.509-SVIDs: %w", err)
	}
	return selectExpectedX509(svids, expected)
}

func selectExpectedJWT(svids []*jwtsvid.SVID, expected spiffeid.ID) (*jwtsvid.SVID, error) {
	if len(svids) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one JWT-SVID, got %d", ErrIdentitySelection, len(svids))
	}
	if svids[0] == nil || svids[0].ID != expected {
		return nil, fmt.Errorf("%w: JWT-SVID does not match configured identity", ErrIdentitySelection)
	}
	return svids[0], nil
}

func selectExpectedX509(svids []*x509svid.SVID, expected spiffeid.ID) (*x509svid.SVID, error) {
	if len(svids) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one X.509-SVID, got %d", ErrIdentitySelection, len(svids))
	}
	if svids[0] == nil || svids[0].ID != expected {
		return nil, fmt.Errorf("%w: X.509-SVID does not match configured identity", ErrIdentitySelection)
	}
	return svids[0], nil
}

func validateAudiences(audiences []string) ([]string, error) {
	if len(audiences) == 0 {
		return nil, fmt.Errorf("%w: at least one JWT audience is required", ErrInvalidOptions)
	}
	clean := make([]string, len(audiences))
	seen := make(map[string]struct{}, len(audiences))
	for i, audience := range audiences {
		clean[i] = strings.TrimSpace(audience)
		if clean[i] == "" {
			return nil, fmt.Errorf("%w: JWT audience cannot be empty", ErrInvalidOptions)
		}
		if _, ok := seen[clean[i]]; ok {
			return nil, fmt.Errorf("%w: duplicate JWT audience", ErrInvalidOptions)
		}
		seen[clean[i]] = struct{}{}
	}
	return clean, nil
}
