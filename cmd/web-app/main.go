package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/agent"
	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/webapp"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/agent/web-app")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()

	gatewayPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp")
	if err != nil {
		log.Fatal(err)
	}
	gatewayHTTP, err := corespiffe.NewHTTPClient(ctx, source, gatewayPeer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	pfHTTP, err := demoenv.PFHTTPClient()
	if err != nil {
		log.Fatal(err)
	}
	oidcHTTP, err := localOIDCBackchannelClient(pfHTTP)
	if err != nil {
		log.Fatal(err)
	}
	exchangeEndpoint := must("PF_TOKEN_ENDPOINT")
	exchange, err := pingfederate.NewClient(exchangeEndpoint, must("PF_CLIENT_ID"), must("PF_CLIENT_SECRET"), pfHTTP)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.Verifier()
	if err != nil {
		log.Fatal(err)
	}
	remoteAudit, err := demoenv.AuditRemote(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	auditSink, err := audit.NewFanout(audit.NewJSONSink(os.Stdout), remoteAudit)
	if err != nil {
		log.Fatal(err)
	}
	gatewayURL, err := demoenv.URL("MCP_GATEWAY_URL")
	if err != nil {
		log.Fatal(err)
	}
	runner := agent.Runner{
		SPIFFE: provider, Exchange: exchange, Verifier: verifier, Audit: auditSink, HTTP: gatewayHTTP,
		ActorAudience: "urn:pingfederate:wai:token-exchange", ExchangeAudience: "mcp-gateway", TransactionAudience: "urn:wai:mcp-gateway",
		GatewayURL: gatewayURL.String(), AgentID: "urn:agent:web-app", WorkloadID: "spiffe://example.org/agent/web-app", AuditTarget: "web-app",
	}
	handler, err := webapp.New(webapp.Config{
		AuthorizationEndpoint: must("OIDC_AUTHORIZATION_ENDPOINT"), TokenEndpoint: must("OIDC_TOKEN_ENDPOINT"),
		RedirectURI: must("OIDC_REDIRECT_URI"), PublicOrigin: must("WEB_PUBLIC_URL"), ClientID: must("OIDC_CLIENT_ID"), ClientSecret: must("PF_WEB_CLIENT_SECRET"),
		Scopes: []string{"openid", "mcp:invoke"}, CookieName: "__Host-wai_session", SessionTTL: time.Hour, PreAuthTTL: 5 * time.Minute, MaximumSessions: 1000,
		HTTPClient: oidcHTTP, Verifier: verifier, Interactions: runner, AllowedInteractions: []webapp.AllowedInteraction{{Tool: "system.whoami", Purpose: "system.whoami"}}, Audit: remoteAudit,
	})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: must("WEB_LISTEN"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(server.ListenAndServeTLS(must("WEB_TLS_CERT_FILE"), must("WEB_TLS_KEY_FILE")))
}

func localOIDCBackchannelClient(base *http.Client) (*http.Client, error) {
	transport, ok := base.Transport.(*http.Transport)
	if !ok || transport == nil || base.Timeout <= 0 {
		return nil, errors.New("local OIDC backchannel requires a bounded HTTP transport")
	}
	clone := transport.Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	clone.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "localhost:9031" {
			return nil, errors.New("unexpected local OIDC backchannel address")
		}
		return dialer.DialContext(ctx, network, "host.docker.internal:9031")
	}
	return &http.Client{Timeout: base.Timeout, Transport: clone}, nil
}

func must(name string) string {
	value, err := demoenv.Required(name)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
