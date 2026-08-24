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
	for _, required := range []string{"$jwtKeys.Count -lt 1", "$seenKeyIDs.ContainsKey($source.kid)", "$source.kty -ne 'EC'", "$source.crv -ne 'P-256'", "use='sig'", "alg='ES256'"} {
		if !strings.Contains(script, required) {
			t.Fatalf("JWKS export missing fail-closed check %q", required)
		}
	}
}

func TestGeneratedInputsRejectAmbiguousOrMalformedRotatedJWKS(t *testing.T) {
	b, err := os.ReadFile("scripts/generate_pf13_1_tfvars.py")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"not jwks_keys",
		"len(set(key_ids)) != len(key_ids)",
		`key.get("kty") != "EC"`,
		`key.get("crv") != "P-256"`,
		`key.get("alg") != "ES256"`,
		`not key.get("x")`,
		`not key.get("y")`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("generated PingFederate inputs missing rotated JWKS validation %q", required)
		}
	}
}

func TestLocalProfileBuildAndComposeKeepArtifactsBounded(t *testing.T) {
	composeBytes, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(composeBytes)
	for _, required := range []string{
		"pingidentity/pingfederate:2606-13.1.0@sha256:",
		"./profile:/opt/in:ro",
		"SERVER_PROFILE_UPDATE: \"true\"",
		"${PING_IDENTITY_DEVOPS_USER:?",
		"${PING_IDENTITY_DEVOPS_KEY:?",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("PingFederate profile Compose missing %q", required)
		}
	}
	for _, forbidden := range []string{"PING_IDENTITY_DEVOPS_USER: wai", "PING_IDENTITY_DEVOPS_KEY: wai", ":edge"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("PingFederate profile Compose contains unpinned or embedded material %q", forbidden)
		}
	}

	buildBytes, err := os.ReadFile("../../scripts/build-pingfederate-profile.ps1")
	if err != nil {
		t.Fatal(err)
	}
	build := string(buildBytes)
	for _, required := range []string{
		"clean test package",
		"pingfederate-spiffe-plugins-0.1.0-SNAPSHOT.jar",
		"wai-pingfederate-spiffe-plugins.jar",
		"Get-FileHash",
		"$artifact.Length -lt 1024",
	} {
		if !strings.Contains(build, required) {
			t.Fatalf("PingFederate profile builder missing %q", required)
		}
	}
	for _, forbidden := range []string{"client_secret", "PING_IDENTITY_DEVOPS_KEY", "terraform.tfstate"} {
		if strings.Contains(build, forbidden) {
			t.Fatalf("PingFederate profile builder handles forbidden material %q", forbidden)
		}
	}
}

func TestProfileArtifactUsesExactSecretFreeScratchInventory(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("profile-artifact/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"FROM scratch", "COPY --chmod=0444 profile/hooks/02-get-remote-server-profile.sh.post /profile/hooks/02-get-remote-server-profile.sh.post",
		"COPY --chmod=0444 profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar /profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar",
		"org.opencontainers.image.revision",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("profile artifact Dockerfile missing %q", required)
		}
	}
	for _, forbidden := range []string{"pingidentity/pingfederate", "env_vars", "sdk", "ARG SECRET", "ARG PASSWORD"} {
		if strings.Contains(strings.ToLower(dockerfile), strings.ToLower(forbidden)) {
			t.Fatalf("profile artifact Dockerfile includes forbidden product or secret input %q", forbidden)
		}
	}
	if strings.Count(dockerfile, "--chmod=0444") != 2 {
		t.Fatal("profile artifact must make both allowlisted files read-only")
	}
	if strings.Contains(dockerfile, "COPY profile/") {
		t.Fatal("profile artifact must not copy a directory whose future contents could broaden the artifact")
	}

	scriptBytes, err := os.ReadFile("../../scripts/build-pingfederate-profile-artifact.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)
	for _, required := range []string{
		"build-pingfederate-profile.ps1", "GetRandomFileName", "Compare-Object $expectedContext $actualContext",
		"Compare-Object $expectedOutput $listed", "BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
		"Refusing to publish the profile artifact from a dirty Git tree", "--platform linux/amd64,linux/arm64",
		"--output \"type=tar,dest=$outputTar\"", "Remove-Item -LiteralPath $temporaryRoot",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("profile artifact builder missing fail-closed control %q", required)
		}
	}
	for _, forbidden := range []string{
		"deploy/pingfederate/sdk/runtime-lib", "deploy/pingfederate/profile/env_vars",
		"docker build .", "--build-context", "Write-Output $bytes", "Copy-Item -Recurse",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("profile artifact builder can include forbidden build input %q", forbidden)
		}
	}
}

func TestPluginBuildIsReproducible(t *testing.T) {
	b, err := os.ReadFile("plugins/pom.xml")
	if err != nil {
		t.Fatal(err)
	}
	pom := string(b)
	for _, required := range []string{
		"<project.build.outputTimestamp>2026-01-01T00:00:00Z</project.build.outputTimestamp>",
		"<artifactId>maven-jar-plugin</artifactId><version>3.4.2</version>",
	} {
		if !strings.Contains(pom, required) {
			t.Fatalf("PingFederate plugin build missing reproducibility control %q", required)
		}
	}
	checkBytes, err := os.ReadFile("../../scripts/test-pingfederate-profile-reproducibility.ps1")
	if err != nil {
		t.Fatal(err)
	}
	check := string(checkBytes)
	for _, required := range []string{"Get-FileHash", "$first -ne $second", "throw 'PingFederate profile plugin build is not reproducible.'"} {
		if !strings.Contains(check, required) {
			t.Fatalf("PingFederate reproducibility check missing failure condition %q", required)
		}
	}
}

func TestSDKExtractionUsesOnlyPinnedImageAndFixedPublicJars(t *testing.T) {
	b, err := os.ReadFile("../../scripts/extract-pingfederate-sdk.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"pingidentity/pingfederate:2606-13.1.0@sha256:",
		"wai-pf-sdk-extract-$PID",
		"/opt/server/server/default/lib/$name",
		"$item.Length -lt 1024",
		"$stream.ReadByte() -ne 0x50",
		"$stream.ReadByte() -ne 0x4b",
		"docker rm -f $containerName",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("PingFederate SDK extraction missing bounded control %q", required)
		}
	}
	for _, forbidden := range []string{"latest", ":edge", "client_secret", "PING_IDENTITY_DEVOPS"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PingFederate SDK extraction contains unpinned or secret material %q", forbidden)
		}
	}
}

func TestBulkProfileExportKeepsPrivilegedMaterialOutsideTrustedProfile(t *testing.T) {
	b, err := os.ReadFile("../../scripts/export-pingfederate-profile.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"https://localhost:9999/",
		"ResponseHeadersRead",
		"MaximumResponseBytes",
		"FixedTimeEquals",
		"RemoteCertificateNameMismatch",
		"ping-bulkexport-tools@sha256:",
		"'--network', 'none'",
		"'--read-only'",
		"'--cap-drop', 'ALL'",
		"target=$containerConfig,readonly",
		"deploy/pingfederate/generated/bulk-export",
		"An allowlisted PingFederate resource contains an unexpected application object.",
		"An allowlisted PingFederate resource contains a duplicate application object.",
		"The application profile candidate contains a residual encrypted field.",
		"The application profile candidate contains a literal credential field.",
		"The application profile candidate has an unexpected external input.",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("bulk profile export missing fail-closed control %q", required)
		}
	}
	for _, forbidden := range []string{
		"2FederateM0re",
		"administrator:",
		"ping-bulkexport-tools:latest",
		"-k",
		"SkipCertificateCheck",
		"deploy/pingfederate/profile/instance/bulk-config",
		"'/administrativeAccounts'",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("bulk profile export contains unsafe behavior %q", forbidden)
		}
	}
}

func TestCleanBootstrapOwnsOnlyRandomIsolatedResources(t *testing.T) {
	b, err := os.ReadFile("../../scripts/test-pingfederate-clean-bootstrap.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"RandomNumberGenerator]::Fill",
		`"wai-pf-clean-$suffix"`,
		`"wai-pf-clean-output-$suffix"`,
		"'127.0.0.1::9999'",
		"'127.0.0.1::9031'",
		"HealthTimeoutSeconds",
		"$attempt -le 12",
		"The isolated PingFederate certificate did not become valid within 60 seconds.",
		"PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS = 'false'",
		"PINGFEDERATE_PROVIDER_CA_CERTIFICATE_PEM_FILES",
		"PF_ADMIN_INSECURE = 'false'",
		"SSL_CERT_FILE",
		"PF_CA_FILE",
		"pf13_1.auto.tfvars.json",
		"Isolated Terraform TLS phase",
		"-target=pingfederate_keypairs_ssl_server_key.local_runtime",
		"-target=pingfederate_keypairs_ssl_server_settings.local_runtime",
		"The Terraform-managed PingFederate certificate did not become valid within 90 seconds.",
		"verify_live_token_exchange.py",
		"Isolated live token-exchange verification did not pass within 60 seconds.",
		"^wai-pf-clean-[0-9a-f]{16}$",
		"^wai-pf-clean-output-[0-9a-f]{16}$",
		"deploy/pingfederate/generated/clean-bootstrap/",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("clean bootstrap missing isolation or failure control %q", required)
		}
	}
	for _, forbidden := range []string{
		"wai-pingfederate-13-1",
		"pingfederate-output",
		"9999:9999",
		"9031:9031",
		"terraform destroy",
		"docker system prune",
		"docker volume prune",
		"INSECURE_TRUST_ALL_TLS = 'true'",
		"PF_ADMIN_INSECURE = 'true'",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("clean bootstrap contains unsafe shared or insecure behavior %q", forbidden)
		}
	}
}

func TestBootstrapMaterialIsStrongGeneratedAndIgnored(t *testing.T) {
	b, err := os.ReadFile("../../scripts/generate-pingfederate-bootstrap-material.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{
		"RandomNumberGenerator]::Fill",
		"RSA]::Create(2048)",
		"HashAlgorithmName]::SHA256",
		"AddDnsName('localhost')",
		"AddDnsName('host.docker.internal')",
		"UtcNow.AddMinutes(-5)",
		"ValidDays -gt 30",
		"X509ContentType]::Pkcs12",
		"Refusing to overwrite existing PingFederate bootstrap material.",
		"[Array]::Clear($pfx",
		"PING_IDENTITY_PASSWORD is required",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("bootstrap material generator missing security control %q", required)
		}
	}
	for _, forbidden := range []string{"2FederateM0re", "Get-Random", "AddDays(365)", "BEGIN PRIVATE KEY"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("bootstrap material generator contains unsafe material or behavior %q", forbidden)
		}
	}

	ignoreBytes, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ignoreBytes), "deploy/pingfederate/profile/env_vars") {
		t.Fatal("generated PingFederate bootstrap material must be ignored")
	}
	composeBytes, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(composeBytes)
	if !strings.Contains(compose, "PING_IDENTITY_PASSWORD: ${PF_ADMIN_PASSWORD:?") || !strings.Contains(compose, "./profile:/opt/in:ro") {
		t.Fatal("PingFederate must receive the administrator password externally and mount its profile read-only")
	}
	hookBytes, err := os.ReadFile("profile/hooks/02-get-remote-server-profile.sh.post")
	if err != nil {
		t.Fatal(err)
	}
	hook := string(hookBytes)
	for _, required := range []string{"/opt/in/env_vars", "test -L", "CONTAINER_ENV", "contains CRLF"} {
		if !strings.Contains(hook, required) {
			t.Fatalf("bootstrap override hook missing fail-closed control %q", required)
		}
	}
	for _, forbidden := range []string{"cat \"${local_env}\" >&2", "set -x"} {
		if strings.Contains(hook, forbidden) {
			t.Fatalf("bootstrap override hook could expose secret material %q", forbidden)
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
	for _, trustedField := range []string{"Agent Bindings", "Transaction Purpose"} {
		if !strings.Contains(managerConfig, trustedField) {
			t.Fatalf("transaction ATM missing trusted configuration precondition %q", trustedField)
		}
	}
	if !strings.Contains(managerConfig, "resource_uris = [\n      # PingFederate requires an absolute URI here.") || !strings.Contains(managerConfig, "var.transaction_audience") {
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
		`ALLOWED_SCOPES = {"mcp:invoke", "mcp.system.whoami"}`,
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

func TestLocalCertificateExportAcceptsBoundedAbsoluteOutput(t *testing.T) {
	b, err := os.ReadFile("../../scripts/export-pf-local-ca.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, required := range []string{"[IO.Path]::IsPathRooted($OutputPath)", "$outputFullPath.tmp", "CreateDirectory($directory)", "addstore Root $outputFullPath"} {
		if !strings.Contains(script, required) {
			t.Fatalf("local certificate export missing safe absolute-path handling %q", required)
		}
	}
	if strings.Contains(script, "Join-Path (Get-Location) $temporary") {
		t.Fatal("local certificate export must not prepend the working directory to an absolute temporary path")
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

func TestTransactionTokensCapabilityProbeIsIsolatedBoundedAndRedacted(t *testing.T) {
	probeBytes, err := os.ReadFile("scripts/probe_transaction_tokens_capabilities.py")
	if err != nil {
		t.Fatal(err)
	}
	probe := string(probeBytes)
	for _, required := range []string{
		`CONTAINER_PATTERN = re.compile(r"^wai-pf-clean-[0-9a-f]{16}$")`,
		`["docker", "port", container, "9031/tcp"]`,
		`parsed_endpoint.hostname != "localhost"`,
		`PF_ADMIN_INSECURE`,
		`MAXIMUM_RESPONSE_BYTES + 1`,
		`object_pairs_hook=unique_object`,
		`NoRedirect()`,
		`"actor_token": actor_token`,
		`del missing_actor["actor_token"]`,
		`"missing_actor_rejected"`,
		`"requested_token_type"] = TXN_TOKEN`,
		`("access_type_trust_domain", access_trust_domain)`,
		`"audience"] = "example.org"`,
		`"request_context"`,
		`"request_details"`,
		`"jwt_signature_verified": True`,
	} {
		if !strings.Contains(probe, required) {
			t.Fatalf("Transaction Tokens capability probe missing security control %q", required)
		}
	}
	for _, forbidden := range []string{
		"CERT_NONE", "check_hostname = False", "error_description", "print(subject_token)",
		"print(actor_token)", "print(token)", "response.read()", "wai-pingfederate-13-1",
	} {
		if strings.Contains(probe, forbidden) {
			t.Fatalf("Transaction Tokens capability probe contains unsafe behavior %q", forbidden)
		}
	}

	harnessBytes, err := os.ReadFile("../../scripts/test-pingfederate-clean-bootstrap.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	for _, required := range []string{
		"[switch]$ProbeTransactionTokens", "$env:PF_CAPABILITY_ISOLATED_CONTAINER = $containerName",
		"probe_transaction_tokens_capabilities.py", "if (-not $exchangeVerified)",
		"-var=enable_transaction_tokens_capability_probe=true",
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("clean-bootstrap harness missing capability gate %q", required)
		}
	}

	terraformBytes, err := os.ReadFile("terraform/transaction_tokens_capability_probe.tf")
	if err != nil {
		t.Fatal(err)
	}
	terraform := string(terraformBytes)
	for _, required := range []string{
		"count = var.enable_transaction_tokens_capability_probe || var.enable_transaction_tokens_inner_profile ? 1 : 0",
		"client_id   = var.trust_domain",
		"pingfederate_oauth_access_token_manager.transaction.manager_id",
	} {
		if !strings.Contains(terraform, required) {
			t.Fatalf("isolated trust-domain selector missing safety gate %q", required)
		}
	}
}

func TestStrictInnerTransactionTokenProfileIsExplicitIsolatedAndFailClosed(t *testing.T) {
	issuerBytes, err := os.ReadFile("plugins/src/main/java/org/example/wai/transaction/TransactionJwtIssuer.java")
	if err != nil {
		t.Fatal(err)
	}
	issuer := string(issuerBytes)
	for _, required := range []string{
		`"txntoken+jwt"`, `claims.setStringClaim("txn"`, `claims.setStringClaim("req_wl"`,
		`claims.setClaim("tctx"`, `"workload_id", attributes.get("workload_id")`,
		`configuredScope.equals(scope)`, `TokenProfile.TRANSACTION_TOKEN_V11`,
	} {
		if !strings.Contains(issuer, required) {
			t.Fatalf("strict inner issuer missing security behavior %q", required)
		}
	}

	profileBytes, err := os.ReadFile("plugins/src/main/java/org/example/wai/transaction/TokenProfile.java")
	if err != nil {
		t.Fatal(err)
	}
	profile := string(profileBytes)
	for _, forbidden := range []string{"AUTO", "detect", "fallback"} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("strict profile must not auto-detect or fall back: %q", forbidden)
		}
	}

	terraformBytes, err := os.ReadFile("terraform/access_token_manager.tf")
	if err != nil {
		t.Fatal(err)
	}
	terraform := string(terraformBytes)
	for _, required := range []string{
		`!var.enable_transaction_tokens_inner_profile || var.enable_transaction_tokens_capability_probe`,
		`value = local.transaction_token_profile`, `value = local.effective_transaction_audience`,
		`value = local.effective_transaction_scope`,
	} {
		if !strings.Contains(terraform, required) {
			t.Fatalf("Terraform strict profile gate missing %q", required)
		}
	}

	variablesBytes, err := os.ReadFile("terraform/variables.tf")
	if err != nil {
		t.Fatal(err)
	}
	variables := string(variablesBytes)
	if !strings.Contains(variables, `variable "enable_transaction_tokens_inner_profile"`) || !strings.Contains(variables, "default     = false") {
		t.Fatal("strict inner profile must be an explicit default-off Terraform switch")
	}

	verifyBytes, err := os.ReadFile("scripts/verify_live_token_exchange.py")
	if err != nil {
		t.Fatal(err)
	}
	verify := string(verifyBytes)
	for _, required := range []string{
		`PF_EXPECT_TRANSACTION_TOKEN_INNER_PROFILE`, `expected_claim_names`,
		`Strict Transaction Token leaked legacy profile claims`, `set(tctx) != {"wai"}`,
		`raise SystemExit("Live token exchange verification refuses disabled TLS validation.")`,
	} {
		if !strings.Contains(verify, required) {
			t.Fatalf("strict live verification missing %q", required)
		}
	}

	harnessBytes, err := os.ReadFile("../../scripts/test-pingfederate-clean-bootstrap.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	for _, required := range []string{
		`[switch]$TestTransactionTokensInnerProfile`,
		`-var=enable_transaction_tokens_inner_profile=true`,
		`$env:PF_EXPECT_TRANSACTION_TOKEN_INNER_PROFILE = 'true'`,
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("isolated strict inner harness missing %q", required)
		}
	}
}

func TestTTSAdapterDeploymentGateIsIsolatedBoundedAndFailClosed(t *testing.T) {
	harnessBytes, err := os.ReadFile("../../scripts/test-pingfederate-clean-bootstrap.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	for _, required := range []string{
		`[switch]$TestTTSAdapter`, `-var=enable_transaction_tokens_inner_profile=true`,
		`--label', 'wai.workload=tts-adapter`, `spiffe://example.org/agent/demo`,
		`spiffe://example.org/gateway/mcp`, `EXPECT_REJECTION=true`,
		`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.`,
		`^wai-tts-adapter-[0-9a-f]{16}$`, `^wai-pf-clean-[0-9a-f]{16}$`,
		`docker rm -f $adapterContainer`, `docker volume rm $volumeName`,
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("isolated TTS adapter gate missing security control %q", required)
		}
	}
	for _, forbidden := range []string{`AuthorizeAny`, `--network host`, `docker system prune`} {
		if strings.Contains(harness, forbidden) {
			t.Fatalf("isolated TTS adapter gate contains unsafe behavior %q", forbidden)
		}
	}
}

func TestStrictCallChainGateProvesTransportAndWorkloadFailures(t *testing.T) {
	harnessBytes, err := os.ReadFile("../../scripts/test-pingfederate-clean-bootstrap.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	for _, required := range []string{
		`[switch]$TestStrictCallChain`, `wai-tts-chain-$suffix`,
		`EXPECT_STRICT_BEARER_REJECTION=true`, `EXPECT_STRICT_TLS_REJECTION=true`,
		`wai.workload=strict-demo-mcp-server`, `spiffe://example.org/mcp/demo-strict`,
		`Authorization\s*[:=]`, `docker network rm $strictNetwork`,
		`^wai-strict-(gateway|mcp|api)-[0-9a-f]{16}$`,
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("strict Call Chain gate missing security control %q", required)
		}
	}
	makefileBytes, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefileBytes), "pf-test-strict-call-chain:") {
		t.Fatal("strict Call Chain gate has no explicit launcher")
	}
}
