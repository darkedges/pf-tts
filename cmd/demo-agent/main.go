package main

import (
	"context"
	"log"
	"os"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/agent"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, "spiffe://example.org/agent/demo")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()
	peer, _ := corespiffe.NewExactPeerPolicy("spiffe://example.org/gateway/mcp")
	httpClient, err := corespiffe.NewHTTPClient(ctx, source, peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	endpoint, err := demoenv.Required("PF_TOKEN_ENDPOINT")
	if err != nil {
		log.Fatal(err)
	}
	clientID, err := demoenv.Required("PF_CLIENT_ID")
	if err != nil {
		log.Fatal(err)
	}
	secret, err := demoenv.Required("PF_CLIENT_SECRET")
	if err != nil {
		log.Fatal(err)
	}
	pfHTTPClient, err := demoenv.PFHTTPClient()
	if err != nil {
		log.Fatal(err)
	}
	pfHTTPClient.Timeout = 10 * time.Second
	exchange, err := pingfederate.NewClient(endpoint, clientID, secret, pfHTTPClient)
	if err != nil {
		log.Fatal(err)
	}
	runner := agent.Runner{SPIFFE: provider, Exchange: exchange, HTTP: httpClient, ActorAudience: "urn:pingfederate:wai:token-exchange", ExchangeAudience: "mcp-gateway", TransactionAudience: "urn:wai:mcp-gateway", GatewayURL: "https://mcp-gateway:8443", DirectAPIURL: "https://demo-api:8445"}
	if err := runner.Run(ctx, os.Getenv("USER_ACCESS_TOKEN"), os.Getenv("TRANSACTION_PURPOSE"), agent.Mode(os.Getenv("AGENT_MODE"))); err != nil {
		log.Fatal(err)
	}
}
