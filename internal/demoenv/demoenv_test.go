package demoenv

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestURLRejectsNonHTTPSAndQuery(t *testing.T) {
	for _, value := range []string{"http://service", "https://service/path?token=secret"} {
		t.Setenv("TEST_URL", value)
		if _, err := URL("TEST_URL"); err == nil {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

func TestCAHTTPClientRequiresExplicitValidTrustAnchor(t *testing.T) {
	t.Setenv("TEST_CA_FILE", "")
	if _, err := CAHTTPClient("TEST_CA_FILE", time.Second); err == nil {
		t.Fatal("missing explicit trust anchor accepted")
	}
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CA_FILE", invalid)
	if _, err := CAHTTPClient("TEST_CA_FILE", time.Second); err == nil {
		t.Fatal("invalid explicit trust anchor accepted")
	}
	cert := &x509.Certificate{Raw: []byte("structurally accepted by PEM pool")}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(invalid, validPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// AppendCertsFromPEM also parses DER, so arbitrary certificate-shaped PEM
	// must still be rejected.
	if _, err := CAHTTPClient("TEST_CA_FILE", time.Second); err == nil {
		t.Fatal("invalid certificate DER accepted")
	}
}

func TestVerifierHTTPClientRejectsInvalidTrustAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PF_CA_FILE", path)
	if _, err := PFHTTPClient(); err == nil {
		t.Fatal("invalid trust anchor accepted")
	}
}

func TestVerifierHTTPClientRejectsMissingTrustAnchor(t *testing.T) {
	t.Setenv("PF_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := PFHTTPClient(); err == nil {
		t.Fatal("missing trust anchor accepted")
	}
}
