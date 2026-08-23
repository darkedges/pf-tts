package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/auditcollector"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/audit/collector")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	store, err := audit.NewStore(audit.StoreConfig{MaximumRecords: 10_000, MaximumFieldBytes: 64 << 10, Retention: time.Hour})
	if err != nil {
		log.Fatal(err)
	}
	callers := []string{
		"spiffe://example.org/agent/demo",
		"spiffe://example.org/agent/web-app",
		"spiffe://example.org/gateway/mcp",
		"spiffe://example.org/mcp/demo",
		"spiffe://example.org/api/demo",
	}
	handler, err := auditcollector.New(auditcollector.Config{Store: store, AllowedSubmitters: callers, QueryCaller: "spiffe://example.org/agent/web-app", MaximumBodyBytes: 64 << 10})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8447", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	peer, err := corespiffe.NewExactPeerPolicy(callers...)
	if err != nil {
		log.Fatal(err)
	}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, peer); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
