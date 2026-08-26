package demoenv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
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

// A configured PF_CA_FILE must be the only trust anchor. When it was merely
// appended to the system pool, an in-cluster caller pointed at PingFederate's
// public address completed the RFC 8693 exchange against the edge that
// terminated that TLS, disclosing the subject and actor tokens. The pin is what
// turns that into a connection failure.
func TestPFHTTPClientPinsTheConfiguredAnchorAndExcludesPublicRoots(t *testing.T) {
	authority, key := selfSignedAuthority(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PF_CA_FILE", caFile)
	client, err := PFHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	pool := client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if pool == nil {
		t.Fatal("a configured PF_CA_FILE produced no explicit trust anchor")
	}
	leaf := signedLeaf(t, authority, key, "tst.ping.darkedges.com")
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "tst.ping.darkedges.com"}); err != nil {
		t.Fatalf("the pinned anchor did not validate its own leaf: %v", err)
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skip("no system certificate pool on this platform")
	}
	if len(system.Subjects()) > 0 && len(pool.Subjects()) >= len(system.Subjects()) {
		t.Fatal("the pinned pool still carries the public certificate authorities")
	}
}

func selfSignedAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wai test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority, key
}

func signedLeaf(t *testing.T, authority *x509.Certificate, key *ecdsa.PrivateKey, dnsName string) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A configured CA file must be the only trust anchor. When it was merely
// appended to the system pool, any public certificate authority also satisfied
// the decision-point channel, so a workload pointed at a public address would
// have sent its authorization request -- user, agent, workload, and transaction
// identifiers -- to whatever terminated that TLS.
func TestCAHTTPClientPinsTheConfiguredAnchorAndExcludesPublicRoots(t *testing.T) {
	authority, key := selfSignedAuthority(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_PDP_CA_FILE", caFile)
	client, err := CAHTTPClient("TEST_PDP_CA_FILE", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool := client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if pool == nil {
		t.Fatal("a configured CA file produced no explicit trust anchor")
	}
	leaf := signedLeaf(t, authority, key, "wai-pingauthorize.wai-pingauthorize.svc.cluster.local")
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "wai-pingauthorize.wai-pingauthorize.svc.cluster.local"}); err != nil {
		t.Fatalf("the pinned anchor did not validate its own leaf: %v", err)
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skip("no system certificate pool on this platform")
	}
	if len(system.Subjects()) > 0 && len(pool.Subjects()) >= len(system.Subjects()) {
		t.Fatal("the pinned pool still carries the public certificate authorities")
	}
}
