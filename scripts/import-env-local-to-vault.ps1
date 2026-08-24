param(
    [string]$EnvFile = '.env.local',
    [string]$Mount = '',
    [string]$PingFederateCAPath = 'wai/pingfederate/ca',
    [string]$TokenExchangeClientPath = 'wai/pingfederate/token-exchange-client',
    [string]$WorkbenchPath = 'wai/workbench',
    [switch]$AllowOverwrite,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$configuredMount = [Environment]::GetEnvironmentVariable('VAULT_KV_MOUNT', 'Process')
if ([string]::IsNullOrWhiteSpace($Mount)) {
    $Mount = if ([string]::IsNullOrWhiteSpace($configuredMount)) { 'secret' } else { $configuredMount }
}
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resolvedEnv = [IO.Path]::GetFullPath((Join-Path $root $EnvFile))
if (-not $resolvedEnv.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Environment file must be inside the repository.' }
if (-not (Test-Path -LiteralPath $resolvedEnv -PathType Leaf)) { throw 'Environment file was not found.' }
if ((Get-Item -LiteralPath $resolvedEnv -Force).LinkType) { throw 'Environment file must not be a symbolic link.' }

$values = @{}
foreach ($line in Get-Content -LiteralPath $resolvedEnv) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { throw 'Environment file contains an invalid entry.' }
    $name = $Matches[1]
    if ($values.ContainsKey($name)) { throw "Environment file contains duplicate key $name." }
    $value = $Matches[2].Trim()
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) { $value = $value.Substring(1, $value.Length - 2) }
    $values[$name] = $value
}

function Required-Value([string]$Name) {
    if (-not $values.ContainsKey($Name) -or [string]::IsNullOrWhiteSpace($values[$Name])) { throw "Required local value $Name is missing." }
    return [string]$values[$Name]
}

$clientID = Required-Value 'PF_CLIENT_ID'
$clientSecret = Required-Value 'PF_CLIENT_SECRET'
$terraformClientSecret = Required-Value 'TF_VAR_token_exchange_client_secret'
if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals([Text.Encoding]::UTF8.GetBytes($clientSecret), [Text.Encoding]::UTF8.GetBytes($terraformClientSecret))) {
    throw 'PF_CLIENT_SECRET conflicts with TF_VAR_token_exchange_client_secret.'
}
$browserSecret = Required-Value 'TF_VAR_browser_client_secret'
$caInput = if ($values.ContainsKey('PF_CA_FILE') -and -not [string]::IsNullOrWhiteSpace($values['PF_CA_FILE'])) {
    [string]$values['PF_CA_FILE']
} else {
    'deploy/pingfederate/generated/local-runtime-ca.pem'
}
$caPath = if ([IO.Path]::IsPathRooted($caInput)) { [IO.Path]::GetFullPath($caInput) } else { [IO.Path]::GetFullPath((Join-Path $root $caInput)) }
if (-not (Test-Path -LiteralPath $caPath -PathType Leaf)) { throw 'PF_CA_FILE does not identify a regular file.' }
$caInfo = Get-Item -LiteralPath $caPath -Force
if ($caInfo.LinkType -or $caInfo.Length -le 0 -or $caInfo.Length -gt 65536) { throw 'PF_CA_FILE must be a non-symlink PEM file no larger than 64 KiB.' }
$caPEM = [IO.File]::ReadAllText($caPath)
if (-not $caPEM.Contains('-----BEGIN CERTIFICATE-----') -or -not $caPEM.Contains('-----END CERTIFICATE-----')) { throw 'PF_CA_FILE does not contain a PEM certificate.' }

foreach ($path in @($PingFederateCAPath, $TokenExchangeClientPath, $WorkbenchPath)) {
    if ($path -notmatch '^[A-Za-z0-9][A-Za-z0-9_./-]{0,254}$' -or $path.Contains('..') -or $path.StartsWith('/') -or $path.EndsWith('/')) { throw 'Vault KV path is invalid.' }
}
if ($Mount -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Vault KV mount is invalid.' }

if ($ValidateOnly) {
    Write-Output 'PASS: local Vault import inputs are valid; no secret was written.'
    exit 0
}
if (-not (Get-Command vault -ErrorAction SilentlyContinue)) { throw 'Vault CLI is required.' }
$vaultAddress = [Environment]::GetEnvironmentVariable('VAULT_ADDR', 'Process')
if ($vaultAddress -notmatch '^https://[^/?#]+(?::[0-9]+)?/?$') { throw 'VAULT_ADDR must be a fixed HTTPS origin.' }
if ([Environment]::GetEnvironmentVariable('VAULT_SKIP_VERIFY', 'Process') -match '^(?i:true|1)$') { throw 'Vault TLS verification must not be disabled.' }
$vaultToken = (& vault print token 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $vaultToken -notmatch '^\S{1,8192}$') { throw 'Vault authentication preflight failed.' }

$httpHandler = [Net.Http.HttpClientHandler]::new()
$httpHandler.AllowAutoRedirect = $false
$vaultCAPath = [Environment]::GetEnvironmentVariable('VAULT_CACERT', 'Process')
if (-not [string]::IsNullOrWhiteSpace($vaultCAPath)) {
    $resolvedVaultCA = [IO.Path]::GetFullPath($vaultCAPath)
    if (-not (Test-Path -LiteralPath $resolvedVaultCA -PathType Leaf)) { throw 'VAULT_CACERT does not identify a regular file.' }
    $vaultCAInfo = Get-Item -LiteralPath $resolvedVaultCA -Force
    if ($vaultCAInfo.LinkType -or $vaultCAInfo.Length -le 0 -or $vaultCAInfo.Length -gt 65536) { throw 'VAULT_CACERT must be a non-symlink PEM file no larger than 64 KiB.' }
    $vaultCA = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($resolvedVaultCA)
    $httpHandler.ServerCertificateCustomValidationCallback = {
        param($Request, $Certificate, $Chain, $PolicyErrors)
        if ($PolicyErrors -eq [Net.Security.SslPolicyErrors]::None) { return $true }
        if (($PolicyErrors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0 -or
            ($PolicyErrors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) -ne 0) { return $false }
        $customChain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $customChain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            $customChain.ChainPolicy.CustomTrustStore.Add($vaultCA)
            $customChain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            return $customChain.Build($Certificate)
        } finally {
            $customChain.Dispose()
        }
    }
}
$httpClient = [Net.Http.HttpClient]::new($httpHandler)
$httpClient.Timeout = [TimeSpan]::FromSeconds(15)

# Trust boundary: the mount type is accepted only from the authenticated Vault
# server over the already validated TLS connection. Never guess a different
# mount after a 404 because that could place credentials in an unintended engine.
$mountRequest = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$($vaultAddress.TrimEnd('/'))/v1/sys/internal/ui/mounts/$([Uri]::EscapeDataString($Mount))")
$mountRequest.Headers.Add('X-Vault-Token', $vaultToken)
$vaultNamespace = [Environment]::GetEnvironmentVariable('VAULT_NAMESPACE', 'Process')
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) { $mountRequest.Headers.Add('X-Vault-Namespace', $vaultNamespace) }
$mountResponse = $null
try {
    $mountResponse = $httpClient.SendAsync($mountRequest).GetAwaiter().GetResult()
    if (-not $mountResponse.IsSuccessStatusCode) {
        throw "Vault KV mount '$Mount' was not found or is not visible to this token (HTTP $([int]$mountResponse.StatusCode)). Set VAULT_KV_MOUNT or pass -Mount with the exact KV v2 mount name."
    }
    $mountMetadata = $mountResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
    if ($mountMetadata.data.type -ne 'kv' -or [string]$mountMetadata.data.options.version -ne '2') {
        throw "Vault mount '$Mount' is not a KV v2 secrets engine; refusing to write."
    }
} finally {
    if ($null -ne $mountResponse) { $mountResponse.Dispose() }
    $mountRequest.Dispose()
}

$payloads = @(
    @{ Path = $PingFederateCAPath; Data = @{ 'ca.pem' = $caPEM } },
    @{ Path = $TokenExchangeClientPath; Data = @{ 'client-id' = $clientID; 'client-secret' = $clientSecret } },
    @{ Path = $WorkbenchPath; Data = @{ 'oidc-client-secret' = $browserSecret; 'token-exchange-client-id' = $clientID; 'token-exchange-client-secret' = $clientSecret } }
)
$completedWrites = 0
try {
    foreach ($payload in $payloads) {
        $escapedPath = ($payload.Path.Split('/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $requestBody = @{ data = $payload.Data }
        if (-not $AllowOverwrite) { $requestBody.options = @{ cas = 0 } }
        $json = $requestBody | ConvertTo-Json -Compress -Depth 4
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, "$($vaultAddress.TrimEnd('/'))/v1/$Mount/data/$escapedPath")
        $request.Headers.Add('X-Vault-Token', $vaultToken)
        if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) { $request.Headers.Add('X-Vault-Namespace', $vaultNamespace) }
        $request.Content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
        $response = $null
        try {
            $response = $httpClient.SendAsync($request).GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                $partial = if ($completedWrites -gt 0) { "$completedWrites earlier path(s) may have new versions" } else { 'no earlier path was written by this run' }
                throw "Vault write failed for path $($payload.Path): HTTP $([int]$response.StatusCode); $partial."
            }
        } finally {
            if ($null -ne $response) { $response.Dispose() }
            $request.Dispose()
        }
        $completedWrites++
    }
} finally {
    $httpClient.Dispose()
    $httpHandler.Dispose()
    if ($null -ne $vaultCA) { $vaultCA.Dispose() }
}
Write-Output 'PASS: imported three reviewed secret records into Vault without printing secret values.'
