package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var ErrInvalidConfig = errors.New("invalid configuration")

type Config struct {
	Server       ServerConfig       `json:"server" yaml:"server"`
	SPIFFE       SPIFFEConfig       `json:"spiffe" yaml:"spiffe"`
	PingFederate PingFederateConfig `json:"pingfederate" yaml:"pingfederate"`
	Transaction  TransactionConfig  `json:"transaction" yaml:"transaction"`
	Agents       []AgentConfig      `json:"agents" yaml:"agents"`
	MCP          MCPConfig          `json:"mcp" yaml:"mcp"`
	Audit        AuditConfig        `json:"audit" yaml:"audit"`
	Web          WebConfig          `json:"web" yaml:"web"`
	OIDC         OIDCConfig         `json:"oidc" yaml:"oidc"`
	Session      SessionConfig      `json:"session" yaml:"session"`
	AuditStore   AuditStoreConfig   `json:"audit_store" yaml:"audit_store"`
}

type ServerConfig struct {
	Listen string `json:"listen" yaml:"listen"`
}
type SPIFFEConfig struct {
	Endpoint    string `json:"endpoint" yaml:"endpoint"`
	TrustDomain string `json:"trust_domain" yaml:"trust_domain"`
}
type PingFederateConfig struct {
	Issuer              string   `json:"issuer" yaml:"issuer"`
	TokenEndpoint       string   `json:"token_endpoint" yaml:"token_endpoint"`
	JWKSURI             string   `json:"jwks_uri" yaml:"jwks_uri"`
	ClientID            string   `json:"client_id" yaml:"client_id"`
	ClientSecretEnv     string   `json:"client_secret_env" yaml:"client_secret_env"`
	ActorAudience       string   `json:"actor_audience" yaml:"actor_audience"`
	TransactionAudience string   `json:"transaction_audience" yaml:"transaction_audience"`
	AllowedAlgorithms   []string `json:"allowed_algorithms" yaml:"allowed_algorithms"`
}
type TransactionConfig struct {
	DefaultTTLSeconds int      `json:"default_ttl_seconds" yaml:"default_ttl_seconds"`
	MaximumTTLSeconds int      `json:"maximum_ttl_seconds" yaml:"maximum_ttl_seconds"`
	ClockSkewSeconds  int      `json:"clock_skew_seconds" yaml:"clock_skew_seconds"`
	AllowedPurposes   []string `json:"allowed_purposes" yaml:"allowed_purposes"`
}
type AgentConfig struct {
	ID               string   `json:"id" yaml:"id"`
	AllowedSPIFFEIDs []string `json:"allowed_spiffe_ids" yaml:"allowed_spiffe_ids"`
}
type MCPConfig struct {
	Servers []MCPServerConfig `json:"servers" yaml:"servers"`
}
type MCPServerConfig struct {
	Name             string   `json:"name" yaml:"name"`
	URL              string   `json:"url" yaml:"url"`
	AllowedSPIFFEIDs []string `json:"allowed_spiffe_ids" yaml:"allowed_spiffe_ids"`
	Tools            []string `json:"tools" yaml:"tools"`
}
type AuditConfig struct {
	Format        string `json:"format" yaml:"format"`
	IncludeUserID bool   `json:"include_user_id" yaml:"include_user_id"`
}

type WebConfig struct {
	Listen    string `json:"listen" yaml:"listen"`
	PublicURL string `json:"public_url" yaml:"public_url"`
	AgentID   string `json:"agent_id" yaml:"agent_id"`
	SPIFFEID  string `json:"spiffe_id" yaml:"spiffe_id"`
	LocalHTTP bool   `json:"allow_insecure_localhost" yaml:"allow_insecure_localhost"`
}

type OIDCConfig struct {
	Issuer                string   `json:"issuer" yaml:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint" yaml:"token_endpoint"`
	ClientID              string   `json:"client_id" yaml:"client_id"`
	ClientSecretEnv       string   `json:"client_secret_env" yaml:"client_secret_env"`
	RedirectURI           string   `json:"redirect_uri" yaml:"redirect_uri"`
	Scopes                []string `json:"scopes" yaml:"scopes"`
}

type SessionConfig struct {
	CookieName        string `json:"cookie_name" yaml:"cookie_name"`
	CookieSecure      bool   `json:"cookie_secure" yaml:"cookie_secure"`
	CookieSameSite    string `json:"cookie_same_site" yaml:"cookie_same_site"`
	TTLSeconds        int    `json:"ttl_seconds" yaml:"ttl_seconds"`
	PreAuthTTLSeconds int    `json:"pre_auth_ttl_seconds" yaml:"pre_auth_ttl_seconds"`
	MaximumSessions   int    `json:"maximum_sessions" yaml:"maximum_sessions"`
}

type AuditStoreConfig struct {
	Listen            string `json:"listen" yaml:"listen"`
	URL               string `json:"url" yaml:"url"`
	SPIFFEID          string `json:"spiffe_id" yaml:"spiffe_id"`
	MaximumEvents     int    `json:"maximum_events" yaml:"maximum_events"`
	MaximumFieldBytes int    `json:"maximum_field_bytes" yaml:"maximum_field_bytes"`
	RetentionSeconds  int    `json:"retention_seconds" yaml:"retention_seconds"`
}

var environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func (c Config) Validate() error {
	if strings.TrimSpace(c.PingFederate.Issuer) == "" {
		return invalid("pingfederate issuer is required")
	}
	if strings.TrimSpace(c.PingFederate.TokenEndpoint) == "" {
		return invalid("pingfederate token endpoint is required")
	}
	if strings.TrimSpace(c.PingFederate.TransactionAudience) == "" {
		return invalid("transaction audience is required")
	}
	if c.Transaction.MaximumTTLSeconds <= 0 {
		return invalid("transaction maximum TTL must be positive")
	}
	if c.Transaction.DefaultTTLSeconds <= 0 {
		return invalid("transaction default TTL must be positive")
	}
	if c.Transaction.DefaultTTLSeconds > c.Transaction.MaximumTTLSeconds {
		return invalid("transaction default TTL exceeds safety maximum")
	}
	if time.Duration(c.Transaction.MaximumTTLSeconds)*time.Second > time.Minute {
		return invalid("transaction safety maximum cannot exceed 60 seconds")
	}

	agents := make(map[string]struct{}, len(c.Agents))
	bindings := make(map[string]string)
	for _, agent := range c.Agents {
		id := strings.TrimSpace(agent.ID)
		if id == "" {
			return invalid("agent ID is required")
		}
		if _, exists := agents[id]; exists {
			return invalid("duplicate agent ID %q", id)
		}
		agents[id] = struct{}{}
		if len(agent.AllowedSPIFFEIDs) == 0 {
			return invalid("agent %q has no allowed SPIFFE IDs", id)
		}
		for _, rawSPIFFEID := range agent.AllowedSPIFFEIDs {
			spiffeID := strings.TrimSpace(rawSPIFFEID)
			if !validSPIFFEID(spiffeID) {
				return invalid("agent %q has invalid SPIFFE ID", id)
			}
			if existing, exists := bindings[spiffeID]; exists {
				return invalid("SPIFFE ID %q is bound to both %q and %q", spiffeID, existing, id)
			}
			bindings[spiffeID] = id
		}
	}
	if err := c.validateUI(bindings); err != nil {
		return err
	}
	return nil
}

func (c Config) validateUI(bindings map[string]string) error {
	publicURL, err := parseApplicationURL(c.Web.PublicURL, c.Web.LocalHTTP)
	if err != nil || (publicURL.Path != "" && publicURL.Path != "/") {
		return invalid("web public URL must be a secure origin")
	}
	if strings.TrimSpace(c.Web.Listen) == "" || strings.TrimSpace(c.Web.AgentID) == "" || !validSPIFFEID(c.Web.SPIFFEID) {
		return invalid("web listen address and trusted agent/workload binding are required")
	}
	if bindings[c.Web.SPIFFEID] != c.Web.AgentID {
		return invalid("web workload must be bound to its logical agent in trusted configuration")
	}
	issuer, err := parseApplicationURL(c.OIDC.Issuer, false)
	if err != nil || (issuer.Path != "" && issuer.Path != "/") {
		return invalid("OIDC issuer must be a secure origin")
	}
	if strings.TrimSuffix(c.OIDC.Issuer, "/") != strings.TrimSuffix(c.PingFederate.Issuer, "/") {
		return invalid("OIDC issuer must match the configured PingFederate issuer")
	}
	for name, raw := range map[string]string{"authorization endpoint": c.OIDC.AuthorizationEndpoint, "token endpoint": c.OIDC.TokenEndpoint} {
		endpoint, endpointErr := parseApplicationURL(raw, false)
		if endpointErr != nil || endpoint.Scheme != issuer.Scheme || endpoint.Host != issuer.Host || endpoint.Path == "" || endpoint.Path == "/" {
			return invalid("OIDC %s must be a secure endpoint on the issuer origin", name)
		}
	}
	redirect, err := parseApplicationURL(c.OIDC.RedirectURI, c.Web.LocalHTTP)
	if err != nil || redirect.Scheme != publicURL.Scheme || redirect.Host != publicURL.Host || redirect.Path == "" || redirect.Path == "/" {
		return invalid("OIDC redirect URI must be a non-root path on the exact web origin")
	}
	if strings.TrimSpace(c.OIDC.ClientID) == "" || !environmentName.MatchString(c.OIDC.ClientSecretEnv) {
		return invalid("OIDC client ID and client secret environment name are required")
	}
	scopes := make(map[string]struct{}, len(c.OIDC.Scopes))
	for _, raw := range c.OIDC.Scopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return invalid("OIDC scopes cannot contain an empty value")
		}
		if _, exists := scopes[scope]; exists {
			return invalid("OIDC scopes cannot contain duplicates")
		}
		scopes[scope] = struct{}{}
	}
	if _, ok := scopes["openid"]; !ok {
		return invalid("OIDC openid scope is required")
	}
	if !strings.HasPrefix(c.Session.CookieName, "__Host-") || !c.Session.CookieSecure || c.Session.CookieSameSite != "Lax" {
		return invalid("session cookie must use __Host-, Secure, and SameSite=Lax")
	}
	if c.Session.TTLSeconds <= 0 || c.Session.TTLSeconds > int((8*time.Hour)/time.Second) || c.Session.PreAuthTTLSeconds <= 0 || c.Session.PreAuthTTLSeconds > int((10*time.Minute)/time.Second) || c.Session.MaximumSessions <= 0 || c.Session.MaximumSessions > 10_000 {
		return invalid("session TTL or capacity exceeds the configured safety bound")
	}
	collectorURL, err := parseApplicationURL(c.AuditStore.URL, false)
	if err != nil || collectorURL.Path != "" && collectorURL.Path != "/" || strings.TrimSpace(c.AuditStore.Listen) == "" || !validSPIFFEID(c.AuditStore.SPIFFEID) {
		return invalid("audit collector URL, listen address, and SPIFFE ID are required")
	}
	if c.AuditStore.SPIFFEID == c.Web.SPIFFEID {
		return invalid("web and audit collector workloads must have distinct SPIFFE IDs")
	}
	if c.AuditStore.MaximumEvents <= 0 || c.AuditStore.MaximumEvents > 100_000 || c.AuditStore.MaximumFieldBytes <= 0 || c.AuditStore.MaximumFieldBytes > 64<<10 || c.AuditStore.RetentionSeconds <= 0 || c.AuditStore.RetentionSeconds > int((24*time.Hour)/time.Second) {
		return invalid("audit storage limits exceed the configured safety bound")
	}
	return nil
}

func parseApplicationURL(raw string, allowInsecureLocalhost bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && allowInsecureLocalhost && isLoopbackHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, ErrInvalidConfig
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func validSPIFFEID(raw string) bool {
	_, err := spiffeid.FromString(strings.TrimSpace(raw))
	return err == nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}
