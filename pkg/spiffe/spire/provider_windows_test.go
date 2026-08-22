//go:build windows

package spire

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func TestWindowsNamedPipeWorkloadAPIEndpoint(t *testing.T) {
	if err := workloadapi.ValidateAddress("npipe:spire-agent/public/api"); err != nil {
		t.Fatalf("SPIRE Windows named-pipe endpoint rejected: %v", err)
	}
	if err := workloadapi.ValidateAddress("npipe://remote-host/pipe/spire"); err == nil {
		t.Fatal("remote named-pipe endpoint must not be accepted as a local Workload API")
	}
}
