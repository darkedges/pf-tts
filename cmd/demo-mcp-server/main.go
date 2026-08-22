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
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/mcp/demo")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	apiPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/api/demo")
	if err != nil {
		log.Fatal(err)
	}
	apiClient, err := corespiffe.NewHTTPClient(ctx, source, apiPeer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	apiURL, err := demoenv.URL("DEMO_API_URL")
	if err != nil {
		log.Fatal(err)
	}
	handler, err := mcp.NewDemoServerHandlerWithAPI(mcp.DemoServerOptions{APIClient: apiClient, APIURL: apiURL})
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.Verifier()
	if err != nil {
		log.Fatal(err)
	}
	auth, err := demoenv.Middleware("urn:wai:mcp-gateway", verifier, "spiffe://example.org/gateway/mcp", "demo-mcp-server")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8444", Handler: auth.Handler(handler), ReadHeaderTimeout: 5 * time.Second}
	peer, _ := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp")
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, peer); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
