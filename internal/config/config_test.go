package config

import (
	"encoding/json"
	"errors"
	"testing"
)

func validConfig() Config {
	return Config{
		PingFederate: PingFederateConfig{Issuer: "https://pf.example.invalid", TokenEndpoint: "https://pf.example.invalid/as/token.oauth2", TransactionAudience: "mcp-gateway"},
		Transaction:  TransactionConfig{DefaultTTLSeconds: 20, MaximumTTLSeconds: 30},
		Agents: []AgentConfig{
			{ID: "urn:agent:demo", AllowedSPIFFEIDs: []string{"spiffe://example.org/agent/demo"}},
			{ID: "urn:agent:web-app", AllowedSPIFFEIDs: []string{"spiffe://example.org/agent/web-app"}},
		},
		Web: WebConfig{Listen: ":8446", PublicURL: "https://localhost:8446", AgentID: "urn:agent:web-app", SPIFFEID: "spiffe://example.org/agent/web-app"},
		OIDC: OIDCConfig{
			Issuer: "https://pf.example.invalid", AuthorizationEndpoint: "https://pf.example.invalid/as/authorization.oauth2",
			TokenEndpoint: "https://pf.example.invalid/as/token.oauth2", ClientID: "wai-web-app", ClientSecretEnv: "PF_WEB_CLIENT_SECRET",
			RedirectURI: "https://localhost:8446/oauth/callback", Scopes: []string{"openid", "mcp:invoke"},
		},
		Session: SessionConfig{CookieName: "__Host-wai_session", CookieSecure: true, CookieSameSite: "Lax", TTLSeconds: 3600, PreAuthTTLSeconds: 300, MaximumSessions: 1000},
		AuditStore: AuditStoreConfig{
			Listen: ":8447", URL: "https://audit-collector:8447", SPIFFEID: "spiffe://example.org/audit/collector",
			MaximumEvents: 10_000, MaximumFieldBytes: 4096, RetentionSeconds: 3600,
		},
	}
}

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.PingFederate.Issuer = "" }},
		{"missing token endpoint", func(c *Config) { c.PingFederate.TokenEndpoint = "" }},
		{"missing audience", func(c *Config) { c.PingFederate.TransactionAudience = "" }},
		{"default TTL above configured maximum", func(c *Config) { c.Transaction.DefaultTTLSeconds = 31 }},
		{"safety maximum above product limit", func(c *Config) { c.Transaction.MaximumTTLSeconds = 61 }},
		{"agent without workload", func(c *Config) { c.Agents[0].AllowedSPIFFEIDs = nil }},
		{"duplicate agent ID", func(c *Config) {
			c.Agents = append(c.Agents, AgentConfig{ID: c.Agents[0].ID, AllowedSPIFFEIDs: []string{"spiffe://example.org/agent/other"}})
		}},
		{"duplicate workload binding", func(c *Config) {
			c.Agents = append(c.Agents, AgentConfig{ID: "urn:agent:other", AllowedSPIFFEIDs: []string{c.Agents[0].AllowedSPIFFEIDs[0]}})
		}},
		{"invalid workload identity", func(c *Config) { c.Agents[0].AllowedSPIFFEIDs = []string{"caller-supplied-agent"} }},
		{"web binding not registered", func(c *Config) { c.Web.AgentID = "urn:agent:forged" }},
		{"shared web and collector identity", func(c *Config) { c.AuditStore.SPIFFEID = c.Web.SPIFFEID }},
		{"insecure public URL", func(c *Config) {
			c.Web.PublicURL = "http://example.com:8446"
			c.OIDC.RedirectURI = "http://example.com:8446/oauth/callback"
		}},
		{"insecure callback", func(c *Config) { c.OIDC.RedirectURI = "http://localhost:8446/oauth/callback" }},
		{"callback origin mismatch", func(c *Config) { c.OIDC.RedirectURI = "https://other.example/oauth/callback" }},
		{"OIDC issuer mismatch", func(c *Config) { c.OIDC.Issuer = "https://other.example" }},
		{"OIDC token endpoint off issuer", func(c *Config) { c.OIDC.TokenEndpoint = "https://attacker.example/token" }},
		{"missing openid scope", func(c *Config) { c.OIDC.Scopes = []string{"mcp:invoke"} }},
		{"invalid secret environment name", func(c *Config) { c.OIDC.ClientSecretEnv = "literal-secret" }},
		{"insecure session cookie", func(c *Config) { c.Session.CookieSecure = false }},
		{"unbounded session TTL", func(c *Config) { c.Session.TTLSeconds = 86400 }},
		{"unbounded pre-auth TTL", func(c *Config) { c.Session.PreAuthTTLSeconds = 601 }},
		{"unbounded session count", func(c *Config) { c.Session.MaximumSessions = 10_001 }},
		{"insecure audit URL", func(c *Config) { c.AuditStore.URL = "http://audit-collector:8447" }},
		{"unbounded audit retention", func(c *Config) { c.AuditStore.RetentionSeconds = 86401 }},
		{"unbounded audit events", func(c *Config) { c.AuditStore.MaximumEvents = 100_001 }},
		{"unbounded audit field", func(c *Config) { c.AuditStore.MaximumFieldBytes = 65537 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid configuration, got %v", err)
			}
		})
	}
}

func TestValidateAllowsExplicitLoopbackHTTPOnlyForLocalDevelopment(t *testing.T) {
	cfg := validConfig()
	cfg.Web.LocalHTTP = true
	cfg.Web.PublicURL = "http://127.0.0.1:8446"
	cfg.OIDC.RedirectURI = "http://127.0.0.1:8446/oauth/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Web.PublicURL = "http://192.0.2.1:8446"
	cfg.OIDC.RedirectURI = "http://192.0.2.1:8446/oauth/callback"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-loopback insecure UI accepted: %v", err)
	}
}

func TestValidateAcceptsSafeConfiguration(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigIsJSONFriendly(t *testing.T) {
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}
