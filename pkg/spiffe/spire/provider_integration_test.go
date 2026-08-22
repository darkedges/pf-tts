//go:build spire_integration

package spire

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveWorkloadAPI(t *testing.T) {
	endpoint := os.Getenv("SPIFFE_ENDPOINT")
	expectedID := os.Getenv("SPIFFE_EXPECTED_ID")
	audience := os.Getenv("SPIFFE_TEST_AUDIENCE")
	if endpoint == "" || expectedID == "" || audience == "" {
		t.Skip("SPIFFE_ENDPOINT, SPIFFE_EXPECTED_ID, and SPIFFE_TEST_AUDIENCE are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider, err := New(ctx, Options{Endpoint: endpoint, ExpectedSPIFFEID: expectedID})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	svid, err := provider.FetchJWTSVID(ctx, []string{audience})
	if err != nil {
		t.Fatal(err)
	}
	if svid.SPIFFEID != expectedID || svid.Token == "" {
		t.Fatal("Workload API returned an empty or unexpected JWT-SVID")
	}
}
