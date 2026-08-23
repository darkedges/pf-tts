package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestLocalOIDCBackchannelRequiresBoundedTransportAndRejectsOtherAddresses(t *testing.T) {
	if _, err := localOIDCBackchannelClient(&http.Client{}); err == nil {
		t.Fatal("unbounded OIDC backchannel client accepted")
	}
	client, err := localOIDCBackchannelClient(&http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "attacker.example:9031"); err == nil {
		t.Fatal("OIDC backchannel dialed an untrusted address")
	}
}
