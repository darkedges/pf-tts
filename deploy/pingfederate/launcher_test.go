package pingfederate

import (
	"os"
	"strings"
	"testing"
)

func TestPythonLauncherLoadsDotenvWithoutEvaluation(t *testing.T) {
	b, err := os.ReadFile("../../scripts/run-python.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, forbidden := range []string{"Invoke-Expression", "iex ", "cmd /c"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("dotenv loader must not execute values: found %q", forbidden)
		}
	}
	if !strings.Contains(script, "[A-Za-z_][A-Za-z0-9_]*") || !strings.Contains(script, "SetEnvironmentVariable") {
		t.Fatal("dotenv loader must validate names and set values without evaluation")
	}
}

func TestPluginDiscoveryDoesNotEchoAdminAPIErrorBodies(t *testing.T) {
	b, err := os.ReadFile("scripts/discover_pf_plugins.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	if strings.Contains(script, "e.read()") {
		t.Fatal("plugin discovery must not echo an Admin API error body")
	}
	if !strings.Contains(script, "/passwordCredentialValidators/descriptors") {
		t.Fatal("plugin discovery must capture the reviewed lab credential-validator descriptor")
	}
	if !strings.Contains(script, "/idp/adapters/descriptors") {
		t.Fatal("plugin discovery must capture hosted-login adapter descriptors before browser client configuration")
	}
}

func TestSpireJWKSExportRejectsAmbiguousOrNonSigningKeys(t *testing.T) {
	b, err := os.ReadFile("../../scripts/spire-export-jwks.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{"$jwtKeys.Count -ne 1", "$source.kty -ne 'EC'", "$source.crv -ne 'P-256'", "use='sig'", "alg='ES256'"} {
		if !strings.Contains(script, required) {
			t.Fatalf("JWKS export missing fail-closed check %q", required)
		}
	}
}

func TestUserAndTransactionAccessTokenManagersAreDistinct(t *testing.T) {
	user, err := os.ReadFile("terraform/user_access_token_manager.tf")
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := os.ReadFile("terraform/access_token_manager.tf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(user), `manager_id = "waiUserAccessToken"`) ||
		!strings.Contains(string(user), "ReferenceBearerAccessTokenManagementPlugin") {
		t.Fatal("user tokens must use the dedicated PF-managed reference ATM")
	}
	if strings.Contains(string(transaction), `manager_id = "waiUserAccessToken"`) {
		t.Fatal("transaction ATM must not collapse into the user-token ATM")
	}
}

func TestTransactionSigningKeyIsPFManaged(t *testing.T) {
	b, err := os.ReadFile("terraform/transaction_signing_key.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{`key_algorithm       = "RSA"`, `key_size            = 2048`, `signature_algorithm = "SHA256withRSA"`} {
		if !strings.Contains(config, required) {
			t.Fatalf("managed signing key missing %q", required)
		}
	}
	for _, forbidden := range []string{"file_data", "password", "private"} {
		if strings.Contains(strings.ToLower(config), forbidden) {
			t.Fatalf("managed signing key must not import private material: %q", forbidden)
		}
	}
	for _, required := range []string{"static_jwks_enabled = true", "rsa_active_cert_ref", "rsa_active_key_id", "rsa_publish_x5c_parameter"} {
		if !strings.Contains(config, required) {
			t.Fatalf("transaction signing key must be published through PF JWKS: %q", required)
		}
	}
}

func TestTerraformLauncherDoesNotEvaluateOrPersistCredentials(t *testing.T) {
	b, err := os.ReadFile("../../scripts/run-pf-terraform.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, forbidden := range []string{"Invoke-Expression", "TF_VAR_pf_admin_password", "Set-Content", "Add-Content"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("Terraform launcher contains unsafe credential handling %q", forbidden)
		}
	}
	for _, required := range []string{"PF_ADMIN_URL must be an absolute HTTPS URL", "PINGFEDERATE_PROVIDER_PASSWORD", "PINGFEDERATE_PROVIDER_PRODUCT_VERSION"} {
		if !strings.Contains(script, required) {
			t.Fatalf("Terraform launcher missing %q", required)
		}
	}
}

func TestGatewaySecretGeneratorUsesCSPRNGAndNeverPrintsSecret(t *testing.T) {
	b, err := os.ReadFile("../../scripts/set-mcp-gateway-local-secret.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{"RandomNumberGenerator]::Create", "$rng.GetBytes($bytes)", "$rng.Dispose()", "Refusing duplicate", "[Array]::Clear"} {
		if !strings.Contains(script, required) {
			t.Fatalf("gateway secret generator missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"Write-Output $secret", "Write-Host $secret", "Get-Random"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("gateway secret generator contains unsafe behavior %q", forbidden)
		}
	}
}

func TestBrowserSecretGeneratorUsesCSPRNGAndNeverPrintsSecret(t *testing.T) {
	b, err := os.ReadFile("../../scripts/set-browser-local-secret.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{"TF_VAR_browser_client_secret", "RandomNumberGenerator]::Create", "$rng.GetBytes($bytes)", "$rng.Dispose()", "Refusing duplicate", "[Array]::Clear"} {
		if !strings.Contains(script, required) {
			t.Fatalf("browser secret generator missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"Write-Output $secret", "Write-Host $secret", "Get-Random"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("browser secret generator contains unsafe behavior %q", forbidden)
		}
	}
}

func TestOAuthClientIgnoresOnlyWriteOnlySecretRepresentations(t *testing.T) {
	b, err := os.ReadFile("terraform/oauth_client.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{"client_auth.secret", "client_auth.encrypted_secret"} {
		if !strings.Contains(config, required) {
			t.Fatalf("OAuth client must suppress provider drift for %q", required)
		}
	}
	for _, forbidden := range []string{"ignore_changes = all", "ignore_changes = [client_auth]"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("OAuth client must not hide authentication-type or unrelated drift: %q", forbidden)
		}
	}
}

func TestBrowserClientUsesOnlyHostedAuthorizationCodeWithPKCE(t *testing.T) {
	b, err := os.ReadFile("terraform/browser_login.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`grant_types                         = ["AUTHORIZATION_CODE"]`,
		`restricted_response_types           = ["code"]`,
		`require_proof_key_for_code_exchange = true`,
		`redirect_uris                       = [var.browser_redirect_uri]`,
		`restrict_scopes   = true`,
		`restrict_to_default_access_token_manager = true`,
		`bypass_approval_page                = false`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("browser OAuth client missing fail-closed control %q", required)
		}
	}
	for _, forbidden := range []string{`"REFRESH_TOKEN"`, `"IMPLICIT"`, `"RESOURCE_OWNER_CREDENTIALS"`, `redirect_uris = ["*`, `require_proof_key_for_code_exchange = false`} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("browser OAuth client enables unsafe capability %q", forbidden)
		}
	}
}

func TestBrowserLoginIdentityComesFromHostedValidatedAdapter(t *testing.T) {
	b, err := os.ReadFile("terraform/browser_login.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter`,
		`value = pingfederate_password_credential_validator.lab_user.validator_id`,
		`mapping_id = pingfederate_idp_adapter.browser_login.adapter_id`,
		`type = "IDP_ADAPTER"`,
		`source = { type = "ADAPTER" }`,
		`value  = "username"`,
		`source = { type = "TOKEN" }`,
		`value  = "user_id"`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("browser hosted-login binding missing %q", required)
		}
	}
	for _, forbidden := range []string{`source = { type = "REQUEST" }`, `source = { type = "TEXT" }`, `value  = var.lab_user_name`} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("browser identity must not come from caller or static assertion %q", forbidden)
		}
	}
}

func TestBrowserClientSecretDriftDoesNotHideOtherSettings(t *testing.T) {
	b, err := os.ReadFile("terraform/browser_login.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{"client_auth.secret", "client_auth.encrypted_secret"} {
		if !strings.Contains(config, required) {
			t.Fatalf("browser client must suppress write-only secret drift for %q", required)
		}
	}
	for _, forbidden := range []string{"ignore_changes = all", "ignore_changes = [client_auth]"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("browser client must not hide unrelated drift: %q", forbidden)
		}
	}
}

func TestBrowserVariablesRejectWeakSecretAndAmbiguousRedirect(t *testing.T) {
	b, err := os.ReadFile("terraform/variables.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`length(var.browser_client_secret) >= 32`,
		`^https://[A-Za-z0-9.-]+(:[0-9]+)?/[^?#*]+$`,
		`!strcontains(var.browser_redirect_uri, "*")`,
		`!strcontains(var.browser_redirect_uri, "?")`,
		`!strcontains(var.browser_redirect_uri, "#")`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("browser variable validation missing %q", required)
		}
	}
}

func TestLabUserIdentityComesOnlyFromValidatedCredentialContract(t *testing.T) {
	b, err := os.ReadFile("terraform/lab_user_flow.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`SimpleUsernamePasswordCredentialValidator`,
		`type = "PASSWORD_CREDENTIAL_VALIDATOR"`,
		`value  = "username"`,
		`grant_types = ["RESOURCE_OWNER_CREDENTIALS"]`,
		`restrict_scopes = true`,
		`restrict_to_default_access_token_manager = true`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("lab user flow missing trusted authentication boundary %q", required)
		}
	}
	for _, forbidden := range []string{`type = "REQUEST"`, `type = "TEXT"`, "Relax Password Requirements\", value = \"true"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("lab user identity must not come from caller input or relaxed credentials: %q", forbidden)
		}
	}
	if strings.Contains(config, "USER_NAME") {
		t.Fatal("lab mapping must not invent USER_NAME when the discovered persistent-grant contract contains only USER_KEY")
	}
	if !strings.Contains(config, "depends_on = [pingfederate_oauth_resource_owner_credentials_mapping.lab_user]") {
		t.Fatal("access-token mapping must wait for the PCV grant mapping context")
	}
}

func TestTerraformUsesOnlyDiscoveredProcessorContracts(t *testing.T) {
	processors, err := os.ReadFile("terraform/token_processors.tf")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile("terraform/token_exchange_policy.tf")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := os.ReadFile("terraform/access_token_manager.tf")
	if err != nil {
		t.Fatal(err)
	}

	processorConfig := string(processors)
	policyConfig := string(policy)
	managerConfig := string(manager)
	if strings.Contains(processorConfig, "TOKEN_SUBJECT") || strings.Contains(policyConfig, "TOKEN_SUBJECT") {
		t.Fatal("Terraform must reject invented processor attributes and use only discovered contracts")
	}
	for _, required := range []string{`name = "user_id"`, `name = "sub"`} {
		if !strings.Contains(processorConfig, required) {
			t.Fatalf("validated processor contract missing %q", required)
		}
	}
	if !strings.Contains(policyConfig, `value = "user_id"`) || !strings.Contains(policyConfig, `value = "sub"`) {
		t.Fatal("TEPP must bind user and workload identities to validated processor outputs")
	}
	if !strings.Contains(policyConfig, "subject = {") {
		t.Fatal("TEPP must fulfill PingFederate's mandatory core subject attribute")
	}
	if !strings.Contains(managerConfig, `name = "wai_provider_contract_marker"`) ||
		!strings.Contains(managerConfig, "wai_provider_contract_marker = {") ||
		!strings.Contains(managerConfig, `type = "NO_MAPPING"`) {
		t.Fatal("provider-required ATM extension must remain an explicitly unmapped marker")
	}
	if strings.Contains(managerConfig, `type = "TOKEN_EXCHANGE_PROCESSOR_POLICY"`+"\n"+`        id`) {
		t.Fatal("TEPP fulfillment source is contextual and must not contain an attribute-source ID")
	}
	for _, coreAttribute := range []string{`name = "sub"`, `name = "agent_id"`, `name = "workload_id"`} {
		if strings.Contains(managerConfig, coreAttribute) {
			t.Fatalf("custom ATM core attribute must not be duplicated as an extension: %q", coreAttribute)
		}
	}
	for _, trustedField := range []string{"Allowed Workload SPIFFE ID", "Logical Agent ID", "Transaction Purpose"} {
		if !strings.Contains(managerConfig, trustedField) {
			t.Fatalf("transaction ATM missing trusted configuration precondition %q", trustedField)
		}
	}
	if !strings.Contains(managerConfig, "resource_uris = [\n      var.transaction_audience") {
		t.Fatal("transaction ATM selector must exactly match the validated transaction audience")
	}
}

func TestScopeProvisioningPreservesGlobalSettingsAndRejectsAmbiguity(t *testing.T) {
	b, err := os.ReadFile("scripts/ensure_pf_scope.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		`SCOPE_NAME = "mcp:invoke"`,
		`request("GET", "/oauth/authServerSettings")`,
		`request("PUT", "/oauth/authServerSettings", settings)`,
		`if len(matches) > 1:`,
		`if not isinstance(scopes, list):`,
		`parsed.scheme != "https"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("scope provisioning missing fail-closed behavior %q", required)
		}
	}
	if strings.Contains(script, "print(settings)") || strings.Contains(script, "error.read()") {
		t.Fatal("scope provisioning must not log global settings or server response bodies")
	}
}

func TestAuthSourceInspectionPrintsOnlySafeIdentifiers(t *testing.T) {
	b, err := os.ReadFile("scripts/inspect_pf_auth_sources.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, forbidden := range []string{"print(value)", "print(response)", "error.read()", "configuration"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("auth-source inspection could expose sensitive Admin API data: %q", forbidden)
		}
	}
	for _, required := range []string{"adapterId", "contractId", "passwordCredentialValidators/descriptors", "PF_ADMIN_URL must not contain credentials"} {
		if !strings.Contains(script, required) {
			t.Fatalf("auth-source inspection missing fail-closed behavior %q", required)
		}
	}
}

func TestSubjectTokenVerificationRejectsBadPasswordAndDoesNotPersistToken(t *testing.T) {
	b, err := os.ReadFile("scripts/verify_lab_subject_token.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{"invalid_grant", `scope and set(str(scope).split()) != {"mcp:invoke"}`, "expires_in > 600"} {
		if !strings.Contains(script, required) {
			t.Fatalf("subject-token verification missing failure check %q", required)
		}
	}
	for _, forbidden := range []string{"print(token)", "access_token.json", "write_text", "Path("} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("subject-token verification must not print or persist credentials: %q", forbidden)
		}
	}
}

func TestLiveExchangeVerifiesSignatureBindingsAndNeverPersistsTokens(t *testing.T) {
	b, err := os.ReadFile("scripts/verify_live_token_exchange.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		`header.get("alg") != "RS256"`,
		`kid != "wai-transaction-signing"`,
		"public_key.verify(",
		`"workload_id": "spiffe://example.org/agent/demo"`,
		`"agent_id": "urn:agent:demo"`,
		`claims["exp"] - claims["iat"] != 20`,
		`tampered["actor_token"]`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("live exchange missing security assertion %q", required)
		}
	}
	for _, forbidden := range []string{"print(subject_token)", "print(actor_token)", "print(transaction_token)", "write_text", "write_bytes"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("live exchange must not print or persist raw tokens: %q", forbidden)
		}
	}
}

func TestGatewayAudienceIsAConfidentialRestrictedResourceClient(t *testing.T) {
	b, err := os.ReadFile("terraform/gateway_resource_client.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`client_id   = var.exchange_target_audience`,
		`type   = "SECRET"`,
		`grant_types = ["ACCESS_TOKEN_VALIDATION"]`,
		`restrict_to_default_access_token_manager = true`,
		`validate_using_all_eligible_atms         = false`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("gateway audience client missing security restriction %q", required)
		}
	}
	if strings.Contains(config, `type = "NONE"`) {
		t.Fatal("gateway resource-server client must not allow unauthenticated token validation")
	}
}

func TestLocalPingFederateTLSRemainsVerified(t *testing.T) {
	b, err := os.ReadFile("terraform/local_tls.tf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(b)
	for _, required := range []string{
		`valid_days                = 365`,
		`signature_algorithm       = "SHA256withRSA"`,
		`"host.docker.internal"`,
		`"localhost"`,
		`pingfederate_keypairs_ssl_server_settings`,
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("local PingFederate TLS configuration missing %q", required)
		}
	}
	for _, forbidden := range []string{"insecure_skip_verify", "CERT_NONE", "InsecureSkipVerify"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("local runtime TLS must fail closed on invalid certificates: %q", forbidden)
		}
	}
}

func TestPingFederateGuideKeepsTrustedIdentityBoundary(t *testing.T) {
	b, err := os.ReadFile("../../docs/pingfederate.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := string(b)
	for _, required := range []string{
		"spiffe://example.org/agent/demo -> urn:agent:demo",
		"Never expose `agent_id` as a client-controlled form",
		"overwrites any caller assertion",
		"wrong-audience actor token",
		"Never weaken required-claim checks",
	} {
		if !strings.Contains(guide, required) {
			t.Fatalf("PingFederate guide missing security boundary or failure case %q", required)
		}
	}
}
