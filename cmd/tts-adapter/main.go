package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"example.com/workload-agent-identity/internal/demoenv"
	"example.com/workload-agent-identity/pkg/middleware"
	"example.com/workload-agent-identity/pkg/pingfederate"
	corespiffe "example.com/workload-agent-identity/pkg/spiffe"
	"example.com/workload-agent-identity/pkg/transaction"
	"example.com/workload-agent-identity/pkg/ttsadapter"
	"github.com/go-jose/go-jose/v4"
)

const (
	adapterSPIFFEID = "spiffe://example.org/tts/adapter"
	demoRequesterID = "spiffe://example.org/agent/demo"
	webRequesterID  = "spiffe://example.org/agent/web-app"
	trustDomain     = "example.org"
	strictScope     = "mcp.system.whoami"
)

func main() {
	ctx := context.Background()
	provider, source, err := demoenv.Provider(ctx, adapterSPIFFEID)
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()

	endpoint, err := demoenv.Required("PF_TOKEN_ENDPOINT")
	if err != nil {
		log.Fatal(err)
	}
	clientID, err := demoenv.Required("PF_CLIENT_ID")
	if err != nil {
		log.Fatal(err)
	}
	clientSecret, err := demoenv.Required("PF_CLIENT_SECRET")
	if err != nil {
		log.Fatal(err)
	}
	issuer, err := demoenv.Required("PF_TRANSACTION_ISSUER")
	if err != nil {
		log.Fatal(err)
	}
	jwksURL, err := demoenv.Required("PF_JWKS_URL")
	if err != nil {
		log.Fatal(err)
	}
	pfHTTP, err := demoenv.PFHTTPClient()
	if err != nil {
		log.Fatal(err)
	}
	exchanger, err := pingfederate.NewClient(endpoint, clientID, clientSecret, pfHTTP)
	if err != nil {
		log.Fatal(err)
	}
	keys, err := pingfederate.NewJWKSKeyResolver(jwksURL, pfHTTP, 1<<20)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := transaction.NewTxnTokenVerifier(transaction.TxnTokenVerifierConfig{
		Mode: transaction.ProfileTxnTokenV11, Issuer: issuer, TrustDomain: trustDomain,
		Algorithms: []jose.SignatureAlgorithm{jose.RS256}, ClockSkew: 5 * time.Second,
		MaximumLifetime: 60 * time.Second, MaximumTokenBytes: 16 << 10, MaximumPayloadBytes: 8 << 10,
		MaximumIdentifierBytes: 256, MaximumContextBytes: 2 << 10, MaximumScopes: 1,
		AllowedScopes:         map[string]struct{}{strictScope: {}},
		WorkloadAgentBindings: map[string]string{demoRequesterID: "urn:agent:demo", webRequesterID: "urn:agent:web-app"}, Keys: keys,
	})
	if err != nil {
		log.Fatal(err)
	}
	auditSink, err := demoenv.AuditSink(ctx, source)
	if err != nil {
		log.Fatal(err)
	}
	handler, err := ttsadapter.NewHandler(ttsadapter.Config{
		TrustDomain: trustDomain, Scope: strictScope, EndpointPath: "/as/token.oauth2", MaximumBodyBytes: 48 << 10,
		MaximumTokenBytes: 16 << 10, MaximumExpiresIn: 60, Exchanger: exchanger, Verifier: verifier,
		Caller:        middleware.ImmediateCallerSPIFFEIDFromVerifiedMTLS,
		Audit:         auditSink,
		ReportFailure: func(stage string) { log.Printf("transaction token adapter rejected request at stage=%s", stage) },
	})
	if err != nil {
		log.Fatal(err)
	}
	peer, err := corespiffe.NewExactPeerPolicy(demoRequesterID, webRequesterID)
	if err != nil {
		log.Fatal(err)
	}
	listen := strings.TrimSpace(os.Getenv("TTS_ADAPTER_LISTEN"))
	if listen == "" {
		listen = ":8448"
	}
	server := &http.Server{
		Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
	}
	if err := corespiffe.ConfigureHTTPServer(ctx, server, source, peer); err != nil {
		log.Fatal(err)
	}
	log.Printf("transaction token adapter listening with SPIFFE identity %s", adapterSPIFFEID)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
