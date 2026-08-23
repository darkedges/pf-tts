package pingauthorize_test

import (
	"os"
	"strings"
	"testing"
)

func TestLocalProfilePinsImageAndMountsPolicyReadOnly(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, required := range []string{
		"pingidentity/pingauthorize:edge@sha256:",
		"hostname: pingauthorize-wai",
		"./profile:/opt/in:ro",
		"wai-mcp-authorization.deploymentpackage:/run/wai/wai-mcp-authorization.deploymentpackage:ro",
		"${PING_IDENTITY_DEVOPS_USER:?",
		"${PING_IDENTITY_DEVOPS_KEY:?",
		"external: true",
		"name: docker_wai-app",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("PingAuthorize profile Compose missing %q", required)
		}
	}
	for _, forbidden := range []string{"trustAll", "InsecureSkipVerify", "PING_IDENTITY_DEVOPS_USER: wai", "PING_IDENTITY_DEVOPS_KEY: wai"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("PingAuthorize profile Compose weakens a trust boundary using %q", forbidden)
		}
	}
}

func TestLocalProfileSelectsOnlyRepositoryPolicy(t *testing.T) {
	b, err := os.ReadFile("profile/pd.profile/dsconfig/30-wai-mcp-policy.dsconfig")
	if err != nil {
		t.Fatal(err)
	}
	profile := string(b)
	for _, required := range []string{
		"pdp-mode:embedded",
		"trust-framework-version:v2",
		"deployment-package</run/wai/wai-mcp-authorization.deploymentpackage",
		"deployment-package-source-type:static-file",
	} {
		if !strings.Contains(profile, required) {
			t.Fatalf("PingAuthorize profile missing fail-closed policy setting %q", required)
		}
	}
	if strings.Contains(profile, "simple.SDP") || strings.Contains(profile, "http://") {
		t.Fatal("PingAuthorize profile must not fall back to the sample or a network-loaded policy")
	}
}

func TestNetworkBootstrapRejectsUnexpectedDriver(t *testing.T) {
	b, err := os.ReadFile("../../scripts/ensure-wai-app-network.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"$networkName = 'docker_wai-app'",
		"docker network create --driver bridge $networkName",
		"-ne 'bridge'",
		"throw \"Existing network $networkName must use the bridge driver.\"",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("network bootstrap missing strict check %q", required)
		}
	}
}
