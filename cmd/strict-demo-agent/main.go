package main

import (
	"context"
	"log"
	"os"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/agent"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/agent/demo")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	adapterPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/tts/adapter")
	if err != nil {
		log.Fatal(err)
	}
	adapterClient, err := corespiffe.NewHTTPClient(ctx, source, adapterPeer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	gatewayPeer, err := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp-strict")
	if err != nil {
		log.Fatal(err)
	}
	gatewayClient, err := corespiffe.NewHTTPClient(ctx, source, gatewayPeer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	adapterURL, err := demoenv.Required("TTS_ADAPTER_URL")
	if err != nil {
		log.Fatal(err)
	}
	gatewayURL, err := demoenv.Required("STRICT_MCP_GATEWAY_URL")
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := demoenv.StrictTxnVerifier()
	if err != nil {
		log.Fatal(err)
	}
	runner := agent.StrictRunner{SPIFFE: provider, AdapterHTTP: adapterClient, GatewayHTTP: gatewayClient, AdapterURL: adapterURL, GatewayURL: gatewayURL, Verifier: verifier, MaximumBytes: 16 << 10}
	if err := runner.Run(ctx, os.Getenv("USER_ACCESS_TOKEN")); err != nil {
		log.Fatal(err)
	}
	log.Print("strict Transaction Token call chain completed")
}
