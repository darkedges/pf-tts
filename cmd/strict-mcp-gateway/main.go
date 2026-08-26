package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/authorization"
	"example.com/workload-agent-identity/pkg/mcp"
	"example.com/workload-agent-identity/pkg/middleware"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

const gatewayID, agentID, webAgentID, mcpID = "spiffe://example.org/gateway/mcp-strict", "spiffe://example.org/agent/demo", "spiffe://example.org/agent/web-app", "spiffe://example.org/mcp/demo-strict"

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, gatewayID)
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	peer, err := corespiffe.NewExactPeerPolicy(mcpID)
	if err != nil {
		log.Fatal(err)
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	targetURL, err := demoenv.URL("STRICT_MCP_SERVER_URL")
	if err != nil {
		log.Fatal(err)
	}
	policy, err := configuredAuthorizer(ctx)
	if err != nil {
		log.Fatal(err)
	}
	sink, err := demoenv.AuditSink(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	gateway, err := mcp.NewStrictGatewayWithAuthorizer(client, []mcp.Target{{Name: "demo", URL: targetURL, Tools: map[string]struct{}{"system.whoami": {}}}}, policy, sink, 16<<10)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.StrictTxnVerifierForBindings(demoenv.StrictWorkloadAgentBindings())
	if err != nil {
		log.Fatal(err)
	}
	auth, err := middleware.NewStrictTxnMiddleware(middleware.StrictTxnMiddlewareConfig{Verifier: verifier, MaximumTokenBytes: 16 << 10, AllowedCallers: map[string]struct{}{agentID: {}, webAgentID: {}}, SPIFFEMTLSAlreadyVerified: true, Audit: sink, Service: "strict-mcp-gateway"})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8543", Handler: auth.Handler(gateway), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	inbound, err := corespiffe.NewExactPeerPolicy(agentID, webAgentID)
	if err != nil {
		log.Fatal(err)
	}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, inbound); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// configuredAuthorizer selects the decision point for the strict call chain.
//
// Whichever provider is chosen, it is still wrapped by the signed-route
// authorizer inside NewStrictGatewayWithAuthorizer, so the target and tool are
// re-checked against the signed route before any policy is consulted. The
// provider decides; it does not get to widen the route.
//
// An unrecognised value is a hard failure rather than a fall back to the
// default, because silently enforcing a different policy than the one an
// operator asked for is worse than refusing to start.
func configuredAuthorizer(ctx context.Context) (mcp.Authorizer, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AUTHORIZATION_PROVIDER"))) {
	case "", "opa":
		return authorization.NewOPA(ctx, "/run/wai/authorization.rego", 100*time.Millisecond)
	case "pingauthorize":
		endpoint, err := demoenv.Required("PINGAUTHORIZE_URL")
		if err != nil {
			return nil, err
		}
		client, err := demoenv.CAHTTPClient("PINGAUTHORIZE_CA_FILE", 2*time.Second)
		if err != nil {
			return nil, err
		}
		return authorization.NewPingAuthorize(client, endpoint, 500*time.Millisecond)
	default:
		return nil, fmt.Errorf("unsupported AUTHORIZATION_PROVIDER")
	}
}
