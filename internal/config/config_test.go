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
		Agents:       []AgentConfig{{ID: "urn:agent:demo", AllowedSPIFFEIDs: []string{"spiffe://example.org/agent/demo"}}},
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
