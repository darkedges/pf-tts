param(
    [string]$EnvFile = '.env.local',
    [string]$ParameterizationConfig = 'deploy/pingfederate/bulk-export/pf-config.json',
    [string]$TrustCertificate = 'deploy/pingfederate/generated/local-runtime-ca.pem',
    [string]$OutputDirectory = 'deploy/pingfederate/generated/bulk-export',
    [int]$TimeoutSeconds = 30,
    [int]$MaximumResponseBytes = 16777216
)

$ErrorActionPreference = 'Stop'
$converterImage = 'darkedges/ping-bulkexport-tools@sha256:529707abf1cae9ef372c2b32a7a52146eeff361d8064bdd0ac3479e914bda730'
$allowedConfigKeys = @('expose-parameters', 'remove-config', 'add-config', 'change-value', 'config-aliases', 'sort-arrays', 'search-replace')

function Resolve-ExistingRegularFile([string]$Path, [string]$Description) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a regular, non-symlink file."
    }
    return $item.FullName
}

function Read-LocalEnvironment([string]$Path) {
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines((Resolve-ExistingRegularFile $Path 'Environment file'))) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) { continue }
        $separator = $trimmed.IndexOf('=')
        if ($separator -lt 1) { throw 'The local environment file contains an invalid entry.' }
        $name = $trimmed.Substring(0, $separator).Trim()
        if ($name -notmatch '^[A-Z][A-Z0-9_]*$') { throw 'The local environment file contains an invalid variable name.' }
        $value = $trimmed.Substring($separator + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$name] = $value
    }
    return $values
}

if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 120) { throw 'TimeoutSeconds must be between 1 and 120.' }
if ($MaximumResponseBytes -lt 1024 -or $MaximumResponseBytes -gt 67108864) { throw 'MaximumResponseBytes must be between 1 KiB and 64 MiB.' }

$localEnvironment = Read-LocalEnvironment $EnvFile
foreach ($requiredName in @('PF_ADMIN_URL', 'PF_ADMIN_USERNAME', 'PF_ADMIN_PASSWORD')) {
    if ([string]::IsNullOrWhiteSpace($localEnvironment[$requiredName])) { throw "Missing required local setting: $requiredName." }
}

$adminUri = [Uri]$localEnvironment['PF_ADMIN_URL']
if (-not $adminUri.IsAbsoluteUri -or $adminUri.Scheme -ne 'https' -or $adminUri.Host -ne 'localhost' -or $adminUri.Port -ne 9999 -or $adminUri.AbsolutePath -ne '/') {
    throw 'PF_ADMIN_URL must be exactly the local HTTPS PingFederate origin https://localhost:9999/.'
}
$exportUri = [Uri]::new($adminUri, 'pf-admin-api/v1/bulk/export')

$configPath = Resolve-ExistingRegularFile $ParameterizationConfig 'Parameterization config'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
foreach ($key in $config.Keys) {
    if ($key -notin $allowedConfigKeys) { throw 'The parameterization config contains an unknown top-level field.' }
}
if (-not $config.ContainsKey('expose-parameters') -or $config['expose-parameters'] -isnot [array]) {
    throw 'The parameterization config must contain an expose-parameters array.'
}

$certificatePath = Resolve-ExistingRegularFile $TrustCertificate 'PingFederate trust certificate'
$certificateText = [IO.File]::ReadAllText($certificatePath)
if ([regex]::Matches($certificateText, '-----BEGIN CERTIFICATE-----').Count -ne 1 -or
    [regex]::Matches($certificateText, '-----END CERTIFICATE-----').Count -ne 1) {
    throw 'The PingFederate trust file must contain exactly one certificate.'
}
$certificateBase64 = $certificateText.Replace('-----BEGIN CERTIFICATE-----', '').Replace('-----END CERTIFICATE-----', '') -replace '\s', ''
$trustedCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($certificateBase64))
$now = [DateTime]::UtcNow
if ($trustedCertificate.NotBefore.ToUniversalTime() -gt $now -or $trustedCertificate.NotAfter.ToUniversalTime() -le $now) {
    $trustedCertificate.Dispose()
    throw 'The PingFederate trust certificate is not currently valid.'
}

$handler = [Net.Http.HttpClientHandler]::new()
$trustedBytes = $trustedCertificate.RawData
Add-Type -TypeDefinition @'
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class WaiExactCertificateValidator
{
    public static byte[] TrustedBytes { get; set; }

    public static void Configure(HttpClientHandler handler, byte[] trustedBytes)
    {
        TrustedBytes = trustedBytes;
        handler.ServerCertificateCustomValidationCallback = Validate;
    }

    public static bool Validate(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
    {
        if (certificate == null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
        byte[] trusted = TrustedBytes;
        return trusted != null && CryptographicOperations.FixedTimeEquals(trusted, certificate.RawData);
    }
}
'@
[WaiExactCertificateValidator]::Configure($handler, $trustedBytes)
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
$credentialBytes = [Text.Encoding]::UTF8.GetBytes("$($localEnvironment['PF_ADMIN_USERNAME']):$($localEnvironment['PF_ADMIN_PASSWORD'])")
$request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $exportUri)
$request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Basic', [Convert]::ToBase64String($credentialBytes))
$request.Headers.Add('X-XSRF-Header', 'PingFederate')

$outputRoot = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputDirectory))
if ([IO.Directory]::Exists($outputRoot) -and ((Get-Item -LiteralPath $outputRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'OutputDirectory must not be a symlink or reparse point.'
}
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$rawExport = Join-Path $outputRoot 'data.json'
$temporaryExport = Join-Path $outputRoot 'data.json.tmp'
$applicationExport = Join-Path $outputRoot 'application-data.json'

try {
    $response = $client.Send($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    if (-not $response.IsSuccessStatusCode) { throw "PingFederate bulk export failed with HTTP $([int]$response.StatusCode)." }
    if ($response.Content.Headers.ContentLength -gt $MaximumResponseBytes) { throw 'PingFederate bulk export exceeded the configured response limit.' }
    $inputStream = $response.Content.ReadAsStream()
    $outputStream = [IO.File]::Open($temporaryExport, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(65536)
        $total = 0
        while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $count
            if ($total -gt $MaximumResponseBytes) { throw 'PingFederate bulk export exceeded the configured response limit.' }
            $outputStream.Write($buffer, 0, $count)
        }
    } finally {
        $outputStream.Dispose()
        $inputStream.Dispose()
    }
    Get-Content -LiteralPath $temporaryExport -Raw | ConvertFrom-Json -Depth 100 | Out-Null
    Move-Item -LiteralPath $temporaryExport -Destination $rawExport -Force
} finally {
    if (Test-Path -LiteralPath $temporaryExport) { Remove-Item -LiteralPath $temporaryExport -Force }
    [Array]::Clear($credentialBytes, 0, $credentialBytes.Length)
    $request.Dispose()
    if ($null -ne $response) { $response.Dispose() }
    $client.Dispose()
    $handler.Dispose()
    [WaiExactCertificateValidator]::TrustedBytes = $null
    $trustedCertificate.Dispose()
}

# Bulk import replaces the complete admin configuration. Select only objects
# already owned by this repository; an unknown object must never become trusted
# merely because it was present in the privileged export.
$allowedItems = [ordered]@{
    '/passwordCredentialValidators'              = @('waiLabUserPCV')
    '/oauth/accessTokenManagers'                  = @('waiTransactionToken', 'waiUserAccessToken')
    '/idp/adapters'                               = @('waiBrowserLogin')
    '/idp/tokenProcessors'                        = @('waiSpireJwtSvid', 'waiUserAccessToken')
    '/oauth/tokenExchange/processor/policies'     = @('wai-agent-transaction')
    '/oauth/idpAdapterMappings'                   = @('waiBrowserLogin')
    '/oauth/resourceOwnerCredentialsMappings'     = @('waiLabUserPCV')
    '/oauth/openIdConnect/policies'                = @('waiBrowserOIDC')
    '/oauth/openIdConnect/settings'                = @()
    '/oauth/tokenExchange/generator/settings'      = @()
    '/oauth/clients'                               = @('mcp-gateway', 'wai-agent-token-exchange', 'wai-lab-user', 'wai-web-app')
    '/oauth/accessTokenMappings'                   = @(
        'authz_req|waiBrowserLogin|waiUserAccessToken',
        'password|waiLabUserPCV|waiUserAccessToken',
        'urn:ietf:params:oauth:grant-type:token-exchange|wai-agent-transaction|waiTransactionToken'
    )
    '/authenticationPolicies/default'             = @()
    '/authenticationPolicies/settings'            = @()
}
$identifierNames = @('id', 'clientId')
$bulk = Get-Content -LiteralPath $rawExport -Raw | ConvertFrom-Json -Depth 100
if ($null -eq $bulk.metadata -or @($bulk.operations).Count -lt 1) { throw 'Bulk export is missing metadata or operations.' }
$selectedOperations = [Collections.Generic.List[object]]::new()
foreach ($operation in @($bulk.operations)) {
    if (-not $allowedItems.Contains($operation.resourceType)) { continue }
    if ($operation.operationType -ne 'SAVE' -or -not [string]::IsNullOrEmpty($operation.subResource)) {
        throw 'An allowlisted PingFederate resource has an unexpected operation shape.'
    }
    $expectedIDs = @($allowedItems[$operation.resourceType])
    $items = @($operation.items)
    if ($expectedIDs.Count -eq 0) {
        if ($items.Count -ne 1) { throw 'An allowlisted singleton PingFederate resource is ambiguous.' }
    } else {
        $seen = @{}
        foreach ($item in $items) {
            $identifier = $null
            foreach ($identifierName in $identifierNames) {
                if ($item.PSObject.Properties.Name -contains $identifierName) { $identifier = [string]$item.$identifierName; break }
            }
            if ([string]::IsNullOrWhiteSpace($identifier) -or $identifier -notin $expectedIDs) {
                throw 'An allowlisted PingFederate resource contains an unexpected application object.'
            }
            if ($seen.ContainsKey($identifier)) { throw 'An allowlisted PingFederate resource contains a duplicate application object.' }
            $seen[$identifier] = $true
        }
        foreach ($expectedID in $expectedIDs) {
            if (-not $seen.ContainsKey($expectedID)) { throw 'The bulk export is missing a required application object.' }
        }
    }
    $selectedOperations.Add($operation)
}
foreach ($resourceType in $allowedItems.Keys) {
    if (@($selectedOperations | Where-Object { $_.resourceType -eq $resourceType }).Count -ne 1) {
        throw 'The bulk export is missing or duplicates an allowlisted application resource.'
    }
}
$applicationDocument = [ordered]@{ metadata = $bulk.metadata; operations = $selectedOperations }
[IO.File]::WriteAllText($applicationExport, ($applicationDocument | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))

$containerConfig = '/config/pf-config.json'
$containerExport = '/work/application-data.json'
$containerEnvironment = '/work/env_vars'
$containerOutput = '/work/data.json.subst'
$converterLog = Join-Path $outputRoot 'convert.log'
$dockerArguments = @(
    'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m', '--cpus', '1',
    '--mount', "type=bind,source=$configPath,target=$containerConfig,readonly",
    '--mount', "type=bind,source=$outputRoot,target=/work",
    $converterImage, $containerConfig, $containerExport, $containerEnvironment, $containerOutput
)
$converterMessages = & docker @dockerArguments 2>&1
$converterExitCode = $LASTEXITCODE
[IO.File]::WriteAllLines($converterLog, [string[]]$converterMessages, [Text.UTF8Encoding]::new($false))
if ($converterExitCode -ne 0) { throw "PingFederate parameterization failed; inspect the ignored converter log at $converterLog." }

$parameterizedOutput = Join-Path $outputRoot 'data.json.subst'
Resolve-ExistingRegularFile $parameterizedOutput 'Parameterized output' | Out-Null
Get-Content -LiteralPath $parameterizedOutput -Raw | ConvertFrom-Json -Depth 100 | Out-Null
Resolve-ExistingRegularFile (Join-Path $outputRoot 'env_vars') 'Generated environment properties' | Out-Null
$parameterizedText = [IO.File]::ReadAllText($parameterizedOutput)
if ($parameterizedText -match '"encrypted[A-Za-z0-9_]*"\s*:') {
    throw 'The application profile candidate contains a residual encrypted field.'
}
if ($parameterizedText -match '"(?:password|secret)"\s*:\s*"(?!\$\{[A-Z_a-z][A-Z_a-z0-9]*\}")') {
    throw 'The application profile candidate contains a literal credential field.'
}
if ($parameterizedText -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----') {
    throw 'The application profile candidate contains private key material.'
}
$allowedPlaceholders = @(
    'TF_VAR_browser_client_secret',
    'TF_VAR_lab_user_client_secret',
    'TF_VAR_lab_user_password',
    'TF_VAR_mcp_gateway_client_secret',
    'TF_VAR_token_exchange_client_secret'
)
$placeholderMatches = [regex]::Matches($parameterizedText, '\$\{([^}]+)\}')
$actualPlaceholders = @($placeholderMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
if ($actualPlaceholders.Count -ne $allowedPlaceholders.Count) {
    throw 'The application profile candidate has a missing or unexpected external input.'
}
foreach ($placeholder in $actualPlaceholders) {
    if ($placeholder -notin $allowedPlaceholders) { throw 'The application profile candidate has an unexpected external input.' }
}

Write-Output "Saved sensitive generated artifacts under $outputRoot."
Write-Output 'Review pf-config.json, data.json.subst, and the required variable names before any manual profile promotion.'
