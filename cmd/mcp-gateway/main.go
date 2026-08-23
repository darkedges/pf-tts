package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/authorization"
	"example.com/workload-agent-identity/pkg/mcp"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/gateway/mcp")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	peer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/mcp/demo")
	if err != nil {
		log.Fatal(err)
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	targetURL, err := demoenv.URL("MCP_SERVER_URL")
	if err != nil {
		log.Fatal(err)
	}
	policy, err := authorization.NewOPA(ctx, "/run/wai/authorization.rego", 100*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	sink, err := demoenv.AuditSink(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	gateway, err := mcp.NewGatewayWithAuthorizer(client, []mcp.Target{{Name: "demo", URL: targetURL, Tools: map[string]struct{}{"customer.get": {}, "system.whoami": {}}}}, policy, sink)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.Verifier()
	if err != nil {
		log.Fatal(err)
	}
	auth, err := demoenv.MiddlewareForCallers("urn:wai:mcp-gateway", verifier, []string{"spiffe://example.org/agent/demo", "spiffe://example.org/agent/web-app"}, "mcp-gateway", sink)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8443", Handler: auth.Handler(gateway), ReadHeaderTimeout: 5 * time.Second}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, mustPolicy("spiffe://example.org/agent/demo", "spiffe://example.org/agent/web-app")); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func mustPolicy(ids ...string) corespiffe.ExactPeerPolicy {
	p, err := corespiffe.NewExactPeerPolicy(ids...)
	if err != nil {
		panic(err)
	}
	return p
}
