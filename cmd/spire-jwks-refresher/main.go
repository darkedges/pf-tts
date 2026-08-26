// Command spire-jwks-refresher keeps PingFederate's actor token processor in
// step with SPIRE's JWT authorities.
//
// The processor validates the agent's JWT-SVID against a configured set of
// trusted keys. SPIRE rotates those keys: it publishes a prepared authority
// hours before it signs with it, then activates it. A configured snapshot that
// is never refreshed therefore works until the moment SPIRE activates a key it
// does not contain, at which point every token exchange fails.
//
// This runs on a schedule well inside that publication window, so the processor
// already trusts each key before SPIRE uses it.
//
// It reads SPIRE's published bundle, translates the JWT authorities into exact
// verification keys, and rewrites the processor's key set only when it differs.
// It logs key identifiers and counts. It never logs key material, the
// administrator credential, or an API response body.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	processorID    = "waiSpireJwtSvid"
	jwksField      = "SPIRE JWKS"
	bundleKey      = "bundle.spiffe"
	maximumBody    = 1 << 20
	requestTimeout = 20 * time.Second
)

// jsonWebKey is the subset of a JWK this tool reads or writes. SPIRE publishes
// its JWT authorities with use "jwt-svid", which is not a value a verification
// key selector looks for, and its X.509 authorities carry no key ID at all.
type jsonWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwks struct {
	Keys []jsonWebKey `json:"keys"`
}

func main() {
	if err := run(context.Background()); err != nil {
		// Errors name the stage and never carry a response body or credential.
		log.Fatalf("spire-jwks-refresher: %v", err)
	}
}

func run(ctx context.Context) error {
	adminURL := strings.TrimSpace(os.Getenv("PF_ADMIN_URL"))
	username := strings.TrimSpace(os.Getenv("PF_ADMIN_USERNAME"))
	password := os.Getenv("PF_ADMIN_PASSWORD")
	if adminURL == "" || username == "" || password == "" {
		return errors.New("PF_ADMIN_URL, PF_ADMIN_USERNAME, and PF_ADMIN_PASSWORD are required")
	}
	parsed, err := url.Parse(adminURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("PF_ADMIN_URL must be a credential-free fixed HTTPS URL")
	}

	trusted, err := spireJWTAuthorities(ctx)
	if err != nil {
		return fmt.Errorf("read SPIRE bundle: %w", err)
	}
	log.Printf("SPIRE publishes %d JWT authorities: %s", len(trusted.Keys), keyIDs(trusted))

	admin, err := adminClient()
	if err != nil {
		return fmt.Errorf("build administrator client: %w", err)
	}
	processor, err := readProcessor(ctx, admin, parsed, username, password)
	if err != nil {
		return fmt.Errorf("read actor token processor: %w", err)
	}
	current, index, err := configuredJWKS(processor)
	if err != nil {
		return fmt.Errorf("read configured key set: %w", err)
	}
	log.Printf("the actor processor trusts %d keys: %s", len(current.Keys), keyIDs(current))

	if sameKeySet(current, trusted) {
		log.Printf("no change required")
		return nil
	}
	encoded, err := json.Marshal(trusted)
	if err != nil {
		return fmt.Errorf("encode key set: %w", err)
	}
	fields, ok := processor["configuration"].(map[string]any)["fields"].([]any)
	if !ok {
		return errors.New("the actor processor returned an unexpected configuration shape")
	}
	field, ok := fields[index].(map[string]any)
	if !ok {
		return errors.New("the actor processor returned an unexpected configuration field")
	}
	field["value"] = string(encoded)
	if err := writeProcessor(ctx, admin, parsed, username, password, processor); err != nil {
		return fmt.Errorf("update actor token processor: %w", err)
	}
	log.Printf("updated the actor processor to trust %d keys: %s", len(trusted.Keys), keyIDs(trusted))
	return nil
}

// spireJWTAuthorities reads the bundle SPIRE itself publishes to a ConfigMap and
// keeps current. Reading what SPIRE published, rather than a copy made
// elsewhere, is what makes this safe to run unattended.
func spireJWTAuthorities(ctx context.Context) (jwks, error) {
	namespace := envOr("SPIRE_BUNDLE_NAMESPACE", "spire-system")
	name := envOr("SPIRE_BUNDLE_CONFIGMAP", "spire-bundle")
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return jwks{}, fmt.Errorf("read service account token: %w", err)
	}
	caPEM, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return jwks{}, fmt.Errorf("read API server trust anchor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return jwks{}, errors.New("the API server trust anchor contains no certificate")
	}
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}
	endpoint := fmt.Sprintf("https://%s/api/v1/namespaces/%s/configmaps/%s",
		envOr("KUBERNETES_SERVICE_HOST_PORT", "kubernetes.default.svc"), namespace, name)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return jwks{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return jwks{}, errors.New("the Kubernetes API is unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jwks{}, fmt.Errorf("HTTP %d reading the bundle ConfigMap", response.StatusCode)
	}
	var configMap struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumBody)).Decode(&configMap); err != nil {
		return jwks{}, errors.New("the bundle ConfigMap is not valid JSON")
	}
	raw, ok := configMap.Data[bundleKey]
	if !ok {
		return jwks{}, fmt.Errorf("the bundle ConfigMap has no %s entry", bundleKey)
	}
	var published jwks
	if err := json.Unmarshal([]byte(raw), &published); err != nil {
		return jwks{}, errors.New("the published bundle is not valid JSON")
	}
	return verificationKeys(published)
}

// verificationKeys translates SPIRE's published authorities into exact
// verification keys: only JWT authorities, only public material, with the
// algorithm pinned per key type rather than left for a token header to choose.
func verificationKeys(published jwks) (jwks, error) {
	seen := map[string]struct{}{}
	result := jwks{}
	for _, key := range published.Keys {
		if key.Use != "jwt-svid" {
			continue
		}
		if strings.TrimSpace(key.Kid) == "" {
			return jwks{}, errors.New("a JWT authority has no key ID; refusing an ambiguous trust anchor")
		}
		if _, exists := seen[key.Kid]; exists {
			return jwks{}, fmt.Errorf("JWT authority key ID %s is ambiguous", key.Kid)
		}
		seen[key.Kid] = struct{}{}
		switch key.Kty {
		case "RSA":
			if key.N == "" || key.E == "" {
				return jwks{}, errors.New("an RSA JWT authority is missing public material")
			}
			result.Keys = append(result.Keys, jsonWebKey{Kty: "RSA", Kid: key.Kid, N: key.N, E: key.E, Use: "sig", Alg: "RS256"})
		case "EC":
			if key.Crv != "P-256" {
				return jwks{}, errors.New("an EC JWT authority is not on the reviewed P-256 curve")
			}
			if key.X == "" || key.Y == "" {
				return jwks{}, errors.New("an EC JWT authority is missing public coordinates")
			}
			result.Keys = append(result.Keys, jsonWebKey{Kty: "EC", Crv: "P-256", Kid: key.Kid, X: key.X, Y: key.Y, Use: "sig", Alg: "ES256"})
		default:
			return jwks{}, fmt.Errorf("JWT authority key type %s is outside the reviewed RS256/ES256 allowlist", key.Kty)
		}
	}
	if len(result.Keys) == 0 {
		return jwks{}, errors.New("the published bundle contains no JWT authority")
	}
	return result, nil
}

func adminClient() (*http.Client, error) {
	caFile := strings.TrimSpace(os.Getenv("PF_ADMIN_CA_FILE"))
	if caFile == "" {
		return nil, errors.New("PF_ADMIN_CA_FILE is required; the administrator channel is never trusted implicitly")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("PF_ADMIN_CA_FILE contains no valid PEM certificates")
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}, nil
}

func readProcessor(ctx context.Context, client *http.Client, base *url.URL, username, password string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, processorEndpoint(base), nil)
	if err != nil {
		return nil, err
	}
	applyAdminHeaders(request, username, password)
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("the private administrator channel is unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	var processor map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumBody)).Decode(&processor); err != nil {
		return nil, errors.New("the actor processor is not valid JSON")
	}
	return processor, nil
}

func writeProcessor(ctx context.Context, client *http.Client, base *url.URL, username, password string, processor map[string]any) error {
	body, err := json.Marshal(processor)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, processorEndpoint(base), bytes.NewReader(body))
	if err != nil {
		return err
	}
	applyAdminHeaders(request, username, password)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("the private administrator channel is unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func processorEndpoint(base *url.URL) string {
	return strings.TrimSuffix(base.String(), "/") + "/idp/tokenProcessors/" + url.PathEscape(processorID)
}

func applyAdminHeaders(request *http.Request, username, password string) {
	request.SetBasicAuth(username, password)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-XSRF-Header", "PingFederate")
}

func configuredJWKS(processor map[string]any) (jwks, int, error) {
	configuration, ok := processor["configuration"].(map[string]any)
	if !ok {
		return jwks{}, 0, errors.New("the actor processor has no configuration")
	}
	fields, ok := configuration["fields"].([]any)
	if !ok {
		return jwks{}, 0, errors.New("the actor processor has no configuration fields")
	}
	for index, entry := range fields {
		field, ok := entry.(map[string]any)
		if !ok || field["name"] != jwksField {
			continue
		}
		value, _ := field["value"].(string)
		var configured jwks
		if err := json.Unmarshal([]byte(value), &configured); err != nil {
			return jwks{}, 0, errors.New("the configured key set is not valid JSON")
		}
		return configured, index, nil
	}
	return jwks{}, 0, fmt.Errorf("the actor processor has no %s field", jwksField)
}

// sameKeySet compares by key ID. A key identifier is what selects a verification
// key, so an identical set of identifiers means no rotation has occurred.
func sameKeySet(current, trusted jwks) bool {
	return keyIDs(current) == keyIDs(trusted)
}

func keyIDs(set jwks) string {
	ids := make([]string, 0, len(set.Keys))
	for _, key := range set.Keys {
		ids = append(ids, key.Kid)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
