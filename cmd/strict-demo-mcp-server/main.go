package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/mcp"
	"example.com/workload-agent-identity/pkg/middleware"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

const mcpID, gatewayID, apiID = "spiffe://example.org/mcp/demo-strict", "spiffe://example.org/gateway/mcp-strict", "spiffe://example.org/api/demo-strict"

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, mcpID)
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	peer, err := corespiffe.NewExactPeerPolicy(apiID)
	if err != nil {
		log.Fatal(err)
	}
	client, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	apiURL, err := demoenv.URL("STRICT_DEMO_API_URL")
	if err != nil {
		log.Fatal(err)
	}
	handler, err := mcp.NewStrictDemoServerHandlerWithAPI(mcp.DemoServerOptions{APIClient: client, APIURL: apiURL}, 16<<10)
	if err != nil {
		log.Fatal(err)
	}
	sink, err := demoenv.AuditSink(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.StrictTxnVerifier()
	if err != nil {
		log.Fatal(err)
	}
	auth, err := middleware.NewStrictTxnMiddleware(middleware.StrictTxnMiddlewareConfig{Verifier: verifier, MaximumTokenBytes: 16 << 10, AllowedCallers: map[string]struct{}{gatewayID: {}}, SPIFFEMTLSAlreadyVerified: true, Audit: sink, Service: "strict-demo-mcp-server"})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8544", Handler: auth.Handler(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	inbound, err := corespiffe.NewExactPeerPolicy(gatewayID)
	if err != nil {
		log.Fatal(err)
	}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, inbound); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
