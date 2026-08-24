package dockerlab

import (
	"os"
	"strings"
	"testing"
)

func TestComposeProfilesAndIdentityIsolation(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, required := range []string{`profiles: ["app-only", "local-lab"]`, `profiles: ["local-lab"]`, `profiles: ["txn-token-gate", "txn-token-call-chain"]`, `profiles: ["txn-token-call-chain"]`, "wai.workload: tts-adapter", "wai.workload: strict-mcp-gateway", "wai.workload: strict-demo-mcp-server", "wai.workload: strict-demo-api", "wai.workload: mcp-gateway", "wai.workload: demo-mcp-server", "wai.workload: demo-api", "wai.workload: demo-agent", "wai.workload: web-app", "wai.workload: audit-collector"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("orchestration missing %q", required)
		}
	}
	if !strings.Contains(compose, "${SPIRE_SOCKET_VOLUME:-spire_spire-agent-socket}") {
		t.Fatal("application profile must default to the repository SPIRE Compose socket volume")
	}
	if strings.Count(compose, "wai.workload:") != 11 {
		t.Fatal("Compose must contain the reviewed normal and isolated workload labels")
	}
	for _, required := range []string{"authorization-strict.rego:/run/wai/authorization.rego:ro", "USER_ACCESS_TOKEN: ${USER_ACCESS_TOKEN:?", "TTS_ADAPTER_URL: https://tts-adapter:8448/as/token.oauth2", "STRICT_MCP_GATEWAY_URL: https://strict-mcp-gateway:8543"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("strict isolated profile missing %q", required)
		}
	}
	if strings.Contains(strings.Split(compose, "services:")[0], "tts-adapter") {
		t.Fatal("TTS adapter must not be part of the shared normal application profile")
	}
}

func TestComposeDoesNotContainCredentialValues(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, forbidden := range []string{"2FederateM0re", "Bearer eyJ"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("Compose contains credential material %q", forbidden)
		}
	}
	for _, line := range strings.Split(compose, "\n") {
		if strings.Contains(strings.ToLower(line), "client_secret:") && !strings.Contains(line, "${") {
			t.Fatalf("Compose embeds a client-secret value instead of requiring environment interpolation: %q", line)
		}
	}
	for _, required := range []string{"${PF_CLIENT_SECRET:?", "${USER_ACCESS_TOKEN:-}"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("secret must be externally injected using %q", required)
		}
	}
	for _, required := range []string{"PF_CA_FILE: /run/pingfederate/ca.pem", "local-runtime-ca.pem:/run/pingfederate/ca.pem:ro"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("PingFederate trust anchor must be explicitly mounted using %q", required)
		}
	}
	for _, required := range []string{"server-cert.pem:/run/web/server-cert.pem:ro", "server-key.pem:/run/web/server-key.pem:ro", "PF_WEB_CLIENT_SECRET: ${TF_VAR_browser_client_secret:?", "AUDIT_COLLECTOR_URL: https://audit-collector:8447"} {
		if !strings.Contains(compose, required) {
			t.Fatalf("web/audit runtime wiring missing %q", required)
		}
	}
	if !strings.Contains(compose, "authorization.rego:/run/wai/authorization.rego:ro") {
		t.Fatal("trusted authorization policy must be mounted read-only")
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "PF_ADMIN_INSECURE"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("application Compose must not disable TLS validation using %q", forbidden)
		}
	}
}

func TestLiveLabCoversFailureBoundariesWithoutTokenOutput(t *testing.T) {
	b, err := os.ReadFile("run_live_lab.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{`agent("normal", True)`, `agent("spoof-agent", False)`, `agent("wrong-audience", False)`, `agent("expired-token", False)`, `agent("unapproved-mcp", False)`, `agent("direct-to-api", False)`, `ssl.create_default_context(cafile=`} {
		if !strings.Contains(script, required) {
			t.Fatalf("live lab missing security failure case %q", required)
		}
	}
	for _, required := range []string{`required_targets = {"demo-agent", "mcp-gateway", "demo-mcp-server", "demo-api"}`, `agent_audit_events.append(event)`, `targets_by_transaction.setdefault(transaction_id, set()).add(target)`, `any(targets == required_targets`} {
		if !strings.Contains(script, required) {
			t.Fatalf("live lab missing cross-hop transaction audit assertion %q", required)
		}
	}
	for _, required := range []string{`deadline = time.monotonic() + 10`, `time.sleep(0.25)`, `if logs.returncode != 0`} {
		if !strings.Contains(script, required) {
			t.Fatalf("live lab missing bounded audit-log readiness handling %q", required)
		}
	}
	for _, forbidden := range []string{"print(subject_token)", "write_text", "CERT_NONE", "check_hostname = False"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("live lab weakens validation or persists a token using %q", forbidden)
		}
	}
}

func TestLocalWebTLSGeneratorPreservesStrictLeafTrust(t *testing.T) {
	b, err := os.ReadFile("../../scripts/generate-web-local-tls.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"AddDays(30)",
		"AddDnsName('localhost')",
		"AddIpAddress([Net.IPAddress]::Loopback)",
		"$leaf = $leafRequest.CreateSelfSigned($notBefore, $notAfter)",
		"certutil.exe -f -user -addstore Root",
		"local-web-cert.pem",
		"FindByThumbprint",
		"$rootStore.Remove($match)",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("local web TLS generator missing strict trust control %q", required)
		}
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "--ignore-certificate-errors", "WAI Local Web Development CA", "X509KeyUsageFlags]::KeyCertSign"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("local web TLS generator weakens certificate validation using %q", forbidden)
		}
	}
}

func TestPingFederateLocalTrustRejectsBroadCertificates(t *testing.T) {
	b, err := os.ReadFile("../../scripts/export-pf-local-ca.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"$basicConstraints.CertificateAuthority",
		"$cert.Subject -ne $cert.Issuer",
		"certutil.exe -f -user -addstore Root $outputFullPath",
		"DNS Name=$([regex]::Escape($name))",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("PingFederate local trust missing strict validation %q", required)
		}
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "--ignore-certificate-errors", "CERT_NONE"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PingFederate local trust weakens validation using %q", forbidden)
		}
	}
}

func TestPingAuthorizeLocalTrustValidatesObservedCertificate(t *testing.T) {
	b, err := os.ReadFile("../../scripts/export-pingauthorize-local-cert.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"$HostName -ne 'localhost'",
		"$cert.HasPrivateKey",
		"$cert.Subject -ne $cert.Issuer",
		"$cert.NotBefore.ToUniversalTime()",
		"DNS Name=localhost",
		"IP Address=127\\.0\\.0\\.1",
		"FindByThumbprint",
		"deploy/pingauthorize/generated",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("PingAuthorize certificate bootstrap missing strict check %q", required)
		}
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "--ignore-certificate-errors", "ExportPkcs12"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PingAuthorize certificate bootstrap contains unsafe behavior %q", forbidden)
		}
	}
}

func TestPingAuthorizeRuntimeTrustRequiresServiceIdentity(t *testing.T) {
	b, err := os.ReadFile("../../scripts/export-pingauthorize-runtime-cert.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"$ContainerName -ne 'pingauthorize-wai'",
		"$ExpectedDnsName -ne 'pingauthorize-wai'",
		"$cert.HasPrivateKey",
		"$cert.Subject -ne $cert.Issuer",
		"$cert.NotBefore.ToUniversalTime()",
		`DNS Name=$([regex]::Escape($ExpectedDnsName))`,
		"deploy/pingauthorize/generated",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("PingAuthorize runtime certificate bootstrap missing strict check %q", required)
		}
	}
	for _, forbidden := range []string{"InsecureSkipVerify", "--ignore-certificate-errors", "ExportPkcs12", "ServerName"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PingAuthorize runtime certificate bootstrap contains unsafe behavior %q", forbidden)
		}
	}
}

func TestGatewayPingAuthorizeWiringPreservesTLSAndFailClosedDefault(t *testing.T) {
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, required := range []string{
		"AUTHORIZATION_PROVIDER: ${AUTHORIZATION_PROVIDER:-opa}",
		"PINGAUTHORIZE_URL: ${PINGAUTHORIZE_URL:-https://pingauthorize-wai:1443/governance-engine}",
		"PINGAUTHORIZE_CA_FILE: /run/pingauthorize/ca.pem",
		"runtime-cert.pem:/run/pingauthorize/ca.pem:ro",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("gateway PingAuthorize wiring missing %q", required)
		}
	}
	for _, forbidden := range []string{"http://pingauthorize", "PINGAUTHORIZE_INSECURE", "check_hostname"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("gateway PingAuthorize wiring weakens TLS using %q", forbidden)
		}
	}
}
