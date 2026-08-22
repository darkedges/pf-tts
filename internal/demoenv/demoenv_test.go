package demoenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestURLRejectsNonHTTPSAndQuery(t *testing.T) {
	for _, value := range []string{"http://service", "https://service/path?token=secret"} {
		t.Setenv("TEST_URL", value)
		if _, err := URL("TEST_URL"); err == nil {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
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
