param(
    [string]$EnvFile = '.env.local',
    [string]$BootstrapEnvFile = 'deploy/pingfederate/profile/env_vars',
    [string]$RuntimeCAFile = 'deploy/pingfederate/generated/local-runtime-ca.pem',
    [string]$Mount = '',
    [switch]$IncludePrivilegedBootstrap,
    [switch]$AllowOverwrite,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
if (-not $IncludePrivilegedBootstrap) { throw 'Privileged PingFederate bootstrap import requires -IncludePrivilegedBootstrap.' }
$basePath = 'wai/pingfederate-13-1'
$configuredMount = [Environment]::GetEnvironmentVariable('VAULT_KV_MOUNT', 'Process')
if (-not $Mount) { $Mount = if ($configuredMount) { $configuredMount } else { 'secret' } }
if ($Mount -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Vault KV mount is invalid.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Resolve-ProtectedFile([string]$Path, [int64]$Maximum, [string]$Label) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) { [IO.Path]::GetFullPath($Path) } else { [IO.Path]::GetFullPath((Join-Path $root $Path)) }
    if (-not $resolved.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be inside the repository." }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label was not found." }
    $info = Get-Item -LiteralPath $resolved -Force
    if ($info.LinkType -or $info.Length -le 0 -or $info.Length -gt $Maximum) { throw "$Label must be a bounded non-symlink regular file." }
    return $resolved
}

function Read-UniqueAssignments([string]$Path, [string]$Pattern, [string[]]$AllowedNames, [string]$Label) {
    $result = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch $Pattern) { throw "$Label contains a malformed entry." }
        $name = $Matches[1]
        if ($name -notin $AllowedNames) { throw "$Label contains an unexpected key." }
        if ($result.ContainsKey($name)) { throw "$Label contains a duplicate key." }
        $value = $Matches[2].Trim()
        if (($value.StartsWith("'") -and $value.EndsWith("'")) -or ($value.StartsWith('"') -and $value.EndsWith('"'))) { $value = $value.Substring(1, $value.Length - 2) }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 1048576) { throw "$Label contains an empty or oversized value." }
        $result[$name] = $value
    }
    return $result
}

function Require([hashtable]$Source, [string]$Name, [string]$Label) {
    if (-not $Source.ContainsKey($Name)) { throw "$Label is incomplete." }
    return [string]$Source[$Name]
}

$resolvedEnv = Resolve-ProtectedFile $EnvFile 1MB 'Environment file'
$resolvedBootstrap = Resolve-ProtectedFile $BootstrapEnvFile 2MB 'Bootstrap environment file'
$resolvedCA = Resolve-ProtectedFile $RuntimeCAFile 64KB 'Runtime CA file'
$requiredEnvNames = @('PF_ADMIN_USERNAME', 'PF_ADMIN_PASSWORD', 'PING_IDENTITY_DEVOPS_USER', 'PING_IDENTITY_DEVOPS_KEY', 'PF_CLIENT_ID', 'PF_CLIENT_SECRET', 'TF_VAR_token_exchange_client_secret', 'TF_VAR_browser_client_secret', 'TF_VAR_lab_user_client_secret', 'TF_VAR_lab_user_password', 'TF_VAR_mcp_gateway_client_secret')
$allowedEnvNames = $requiredEnvNames + @('AUTHORIZATION_PROVIDER', 'PF_ADMIN_INSECURE', 'PF_ADMIN_URL', 'PF_JWKS_URL', 'PF_TOKEN_ENDPOINT', 'PF_TRANSACTION_ISSUER', 'PF_TRANSACTION_KEY_ID', 'PINGAUTHORIZE_CA_FILE', 'PINGAUTHORIZE_URL')
$values = Read-UniqueAssignments $resolvedEnv '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$' $allowedEnvNames 'Environment file'
$bootstrapNames = @('dataStores_items_ProvisionerDS_ProvisionerDS_password', 'keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_fileData', 'keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_password', 'serverSettings_systemKeys_items_current_keyData', 'serverSettings_systemKeys_items_pending_keyData', 'PING_IDENTITY_PASSWORD')
$bootstrap = Read-UniqueAssignments $resolvedBootstrap '^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$' $bootstrapNames 'Bootstrap environment file'
foreach ($name in $requiredEnvNames) { $null = Require $values $name 'Environment file' }
foreach ($name in $bootstrapNames) { $null = Require $bootstrap $name 'Bootstrap environment file' }
if ($bootstrap['PING_IDENTITY_PASSWORD'] -ne '${PING_IDENTITY_PASSWORD:?PING_IDENTITY_PASSWORD is required}') { throw 'Bootstrap administrator password must remain an external runtime binding.' }

$left = [Text.Encoding]::UTF8.GetBytes($values['PF_CLIENT_SECRET'])
$right = [Text.Encoding]::UTF8.GetBytes($values['TF_VAR_token_exchange_client_secret'])
try {
    if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($left, $right)) { throw 'Token-exchange client secret inputs conflict.' }
} finally { [Array]::Clear($left, 0, $left.Length); [Array]::Clear($right, 0, $right.Length) }
$caPEM = [IO.File]::ReadAllText($resolvedCA)
if ([regex]::Matches($caPEM, '-----BEGIN CERTIFICATE-----').Count -ne 1 -or [regex]::Matches($caPEM, '-----END CERTIFICATE-----').Count -ne 1 -or $caPEM -notmatch '(?s)^\s*-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----\s*$') { throw 'Runtime CA file must contain exactly one PEM certificate document.' }
try { $caCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($caPEM) } catch { throw 'Runtime CA file contains an invalid certificate.' }
$caCertificate.Dispose()

$payloads = @(
    @{ Path = "$basePath/administrator"; Data = @{ username = $values['PF_ADMIN_USERNAME']; password = $values['PF_ADMIN_PASSWORD'] } },
    @{ Path = "$basePath/devops"; Data = @{ username = $values['PING_IDENTITY_DEVOPS_USER']; key = $values['PING_IDENTITY_DEVOPS_KEY'] } },
    @{ Path = "$basePath/bootstrap-system"; Data = @{
        'provisioner-password' = $bootstrap['dataStores_items_ProvisionerDS_ProvisionerDS_password']; 'ssl-file-data' = $bootstrap['keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_fileData'];
        'ssl-password' = $bootstrap['keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_password']; 'current-system-key' = $bootstrap['serverSettings_systemKeys_items_current_keyData']; 'pending-system-key' = $bootstrap['serverSettings_systemKeys_items_pending_keyData']
    } },
    @{ Path = "$basePath/oauth/token-exchange"; Data = @{ 'client-id' = $values['PF_CLIENT_ID']; 'client-secret' = $values['PF_CLIENT_SECRET'] } },
    @{ Path = "$basePath/oauth/browser"; Data = @{ 'client-id' = 'wai-browser'; 'client-secret' = $values['TF_VAR_browser_client_secret'] } },
    @{ Path = "$basePath/oauth/lab-user"; Data = @{ 'client-id' = 'wai-lab-user'; 'client-secret' = $values['TF_VAR_lab_user_client_secret']; 'user-password' = $values['TF_VAR_lab_user_password'] } },
    @{ Path = "$basePath/oauth/mcp-gateway"; Data = @{ 'client-id' = 'wai-mcp-gateway'; 'client-secret' = $values['TF_VAR_mcp_gateway_client_secret'] } },
    # ca.pem is consumed by Go clients; ca.crt is the ingress-nginx upstream
    # verification key. Both contain the same reviewed public certificate.
    @{ Path = "$basePath/runtime-ca"; Data = @{ 'ca.pem' = $caPEM; 'ca.crt' = $caPEM } }
)
if ($ValidateOnly) { Write-Output 'PASS: isolated privileged Vault inputs are complete and consistent; nothing was written.'; exit 0 }

if (-not (Get-Command vault -ErrorAction SilentlyContinue)) { throw 'Vault CLI is required.' }
$vaultAddress = [Environment]::GetEnvironmentVariable('VAULT_ADDR', 'Process')
if ($vaultAddress -notmatch '^https://[^/?#]+(?::[0-9]+)?/?$') { throw 'VAULT_ADDR must be a fixed HTTPS origin.' }
if ([Environment]::GetEnvironmentVariable('VAULT_SKIP_VERIFY', 'Process') -match '^(?i:true|1)$') { throw 'Vault TLS verification must not be disabled.' }
$vaultToken = (& vault print token 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $vaultToken -notmatch '^\S{1,8192}$') { throw 'Vault authentication preflight failed.' }
$handler = [Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(15)
$namespace = [Environment]::GetEnvironmentVariable('VAULT_NAMESPACE', 'Process')
try {
    $mountRequest = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$($vaultAddress.TrimEnd('/'))/v1/sys/internal/ui/mounts/$Mount")
    $mountRequest.Headers.Add('X-Vault-Token', $vaultToken); if ($namespace) { $mountRequest.Headers.Add('X-Vault-Namespace', $namespace) }
    $mountResponse = $client.SendAsync($mountRequest).GetAwaiter().GetResult()
    try {
        if (-not $mountResponse.IsSuccessStatusCode) { throw 'The configured Vault mount is unavailable; refusing to write.' }
        $metadata = $mountResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        if ($metadata.data.type -ne 'kv' -or [string]$metadata.data.options.version -ne '2') { throw 'The configured Vault mount is not KV v2; refusing to write.' }
    } finally { $mountResponse.Dispose(); $mountRequest.Dispose() }
    $completed = 0
    foreach ($payload in $payloads) {
        $escaped = ($payload.Path.Split('/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $body = @{ data = $payload.Data }; if (-not $AllowOverwrite) { $body.options = @{ cas = 0 } }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, "$($vaultAddress.TrimEnd('/'))/v1/$Mount/data/$escaped")
        $request.Headers.Add('X-Vault-Token', $vaultToken); if ($namespace) { $request.Headers.Add('X-Vault-Namespace', $namespace) }
        $request.Content = [Net.Http.StringContent]::new(($body | ConvertTo-Json -Compress -Depth 4), [Text.Encoding]::UTF8, 'application/json')
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) { $partial = if ($completed) { "$completed earlier path(s) may have new versions" } else { 'no earlier path was written' }; throw "Vault write failed for $($payload.Path): HTTP $([int]$response.StatusCode); $partial." }
        } finally { $response.Dispose(); $request.Dispose() }
        $completed++
    }
} finally { $client.Dispose(); $handler.Dispose() }
Write-Output 'PASS: imported eight isolated PingFederate records without printing secret values.'
