package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/mcp"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/api/demo")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	verifier, err := demoenv.Verifier()
	if err != nil {
		log.Fatal(err)
	}
	auth, err := demoenv.Middleware("urn:wai:mcp-gateway", verifier, "spiffe://example.org/mcp/demo", "demo-api")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8445", Handler: auth.Handler(mcp.DemoAPIHandler()), ReadHeaderTimeout: 5 * time.Second}
	peer, _ := corespiffe.NewExactPeerPolicy("spiffe://example.org/mcp/demo")
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, peer); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
