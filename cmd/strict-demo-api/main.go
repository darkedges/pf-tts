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

const apiID, mcpID = "spiffe://example.org/api/demo-strict", "spiffe://example.org/mcp/demo-strict"

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, apiID)
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	handler, err := mcp.StrictDemoAPIHandler("demo", "system.whoami")
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
	auth, err := middleware.NewStrictTxnMiddleware(middleware.StrictTxnMiddlewareConfig{Verifier: verifier, MaximumTokenBytes: 16 << 10, AllowedCallers: map[string]struct{}{mcpID: {}}, SPIFFEMTLSAlreadyVerified: true, Audit: sink, Service: "strict-demo-api"})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8545", Handler: auth.Handler(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	inbound, err := corespiffe.NewExactPeerPolicy(mcpID)
	if err != nil {
		log.Fatal(err)
	}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, inbound); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
