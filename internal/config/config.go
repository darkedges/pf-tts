package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
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
			if !strings.HasPrefix(spiffeID, "spiffe://") || len(spiffeID) == len("spiffe://") {
				return invalid("agent %q has invalid SPIFFE ID", id)
			}
			if existing, exists := bindings[spiffeID]; exists {
				return invalid("SPIFFE ID %q is bound to both %q and %q", spiffeID, existing, id)
			}
			bindings[spiffeID] = id
		}
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}
