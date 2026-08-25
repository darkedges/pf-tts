package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/agent"
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

	adapterPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/tts/adapter")
	if err != nil {
		log.Fatal(err)
	}
	adapterHTTP, err := corespiffe.NewHTTPClient(ctx, source, adapterPeer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	gatewayPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp-strict")
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
	verifier, err := demoenv.StrictTxnVerifierForBindings(map[string]string{"spiffe://example.org/agent/web-app": "urn:agent:web-app"})
	if err != nil {
		log.Fatal(err)
	}
	remoteAudit, err := demoenv.AuditRemote(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	gatewayURL, err := demoenv.URL("MCP_GATEWAY_URL")
	if err != nil {
		log.Fatal(err)
	}
	adapterURL, err := demoenv.URL("TTS_ADAPTER_URL")
	if err != nil {
		log.Fatal(err)
	}
	runner := agent.StrictRunner{
		SPIFFE: provider, AdapterHTTP: adapterHTTP, GatewayHTTP: gatewayHTTP, AdapterURL: adapterURL.String(), GatewayURL: gatewayURL.String(),
		Verifier: verifier, MaximumBytes: 16 << 10, AgentID: "urn:agent:web-app", WorkloadID: "spiffe://example.org/agent/web-app",
	}
	handler, err := webapp.New(webapp.Config{
		AuthorizationEndpoint: must("OIDC_AUTHORIZATION_ENDPOINT"), TokenEndpoint: must("OIDC_TOKEN_ENDPOINT"),
		RedirectURI: must("OIDC_REDIRECT_URI"), PublicOrigin: must("WEB_PUBLIC_URL"), ClientID: must("OIDC_CLIENT_ID"), ClientSecret: must("PF_WEB_CLIENT_SECRET"),
		Scopes: []string{"openid", "mcp:invoke"}, CookieName: "__Host-wai_session", SessionTTL: time.Hour, PreAuthTTL: 5 * time.Minute, MaximumSessions: 1000,
		HTTPClient: pfHTTP, Verifier: mustOIDCVerifier(), Interactions: runner, AllowedInteractions: []webapp.AllowedInteraction{{Tool: "system.whoami", Purpose: "system.whoami"}}, Audit: remoteAudit,
	})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: must("WEB_LISTEN"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(server.ListenAndServeTLS(must("WEB_TLS_CERT_FILE"), must("WEB_TLS_KEY_FILE")))
}

func mustOIDCVerifier() webapp.IDTokenVerifier {
	verifier, err := demoenv.Verifier()
	if err != nil {
		log.Fatal(err)
	}
	return verifier
}

func must(name string) string {
	value, err := demoenv.Required(name)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
