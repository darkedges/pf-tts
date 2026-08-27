<#
.SYNOPSIS
Import the isolated PingAuthorize 11.1 records into Vault.

.DESCRIPTION
The isolated decision point needs four records: the administrator password it
runs with, the Ping Identity DevOps credential that licenses the product, the TLS
key pair it serves, and the public half of that pair for the strict gateway to
verify it against.

The certificate is generated here rather than left to the product's own
self-signed setup certificate. That certificate is bound to the container
hostname, which in Kubernetes is the pod name and not the Service name the
gateway addresses -- and the adapter refuses both disabled verification and a
ServerName override, so a certificate that does not name the Service is unusable.
Generating it up front also means every record exists before the pod starts,
rather than the gateway waiting on a certificate that only appears after setup.

The private key and the public certificate are deliberately separate records: the
strict gateway's policy grants it the public one only.

The DevOps credential and the administrator password are privileged, so this is a
separate deliberate operator action rather than part of the ordinary application
importer, and it refuses to run without an explicit switch.

Writes are create-only by default so an existing record is never silently
replaced. No secret value is printed, and failures report the path and status
only.
#>
param(
    [string]$EnvFile = '.env.local',
    [string[]]$DnsNames = @(
        'wai-pingauthorize.wai-pingauthorize.svc.cluster.local',
        'wai-pingauthorize.wai-pingauthorize.svc',
        'wai-pingauthorize.wai-pingauthorize',
        'wai-pingauthorize',
        'localhost'
    ),
    [string]$Mount = '',
    [switch]$IncludePrivilegedBootstrap,
    [switch]$AllowOverwrite,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IncludePrivilegedBootstrap) { throw 'Privileged PingAuthorize import requires -IncludePrivilegedBootstrap.' }

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$basePath = 'wai/pingauthorize-11-1'

if ([string]::IsNullOrWhiteSpace($Mount)) { $Mount = [Environment]::GetEnvironmentVariable('VAULT_KV_MOUNT', 'Process') }
if ([string]::IsNullOrWhiteSpace($Mount)) { $Mount = 'secret' }
if ($Mount -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'VAULT_KV_MOUNT must be a simple mount name.' }

function Resolve-ProtectedFile {
    param([string]$Path, [int]$Maximum = 65536)
    $resolved = [IO.Path]::GetFullPath((Join-Path $root $Path))
    if (-not $resolved.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Protected inputs must live inside the repository.'
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Required input is missing: $Path" }
    $info = Get-Item -LiteralPath $resolved -Force
    if ($info.LinkType -or $info.Length -le 0 -or $info.Length -gt $Maximum) {
        throw "Required input must be a bounded regular non-symlink file: $Path"
    }
    return $resolved
}

function Read-UniqueAssignments {
    param([string]$Path, [string[]]$Expected)
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { throw 'Malformed environment assignment encountered.' }
        $name = $Matches[1]; $value = $Matches[2].Trim()
        if ($Expected -notcontains $name) { continue }
        if ($values.ContainsKey($name)) { throw "Duplicate assignment for $name." }
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 4096) { throw "$name is empty or oversized." }
        $values[$name] = $value
    }
    foreach ($name in $Expected) { if (-not $values.ContainsKey($name)) { throw "$name is required in $Path." } }
    return $values
}

$environment = Read-UniqueAssignments -Path (Resolve-ProtectedFile -Path $EnvFile) -Expected @(
    'PING_IDENTITY_DEVOPS_USER', 'PING_IDENTITY_DEVOPS_KEY'
)

# The administrator password is generated here rather than read from a file, so
# the isolated deployment never inherits the product's documented default.
$administratorPassword = [Environment]::GetEnvironmentVariable('PA_ADMIN_PASSWORD', 'Process')
if ([string]::IsNullOrWhiteSpace($administratorPassword)) {
    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $administratorPassword = [Convert]::ToBase64String($bytes).TrimEnd('=') -replace '[^A-Za-z0-9]', 'x'
}
if ($administratorPassword.Length -lt 16) { throw 'The PingAuthorize administrator password must be at least 16 characters.' }
if ($administratorPassword -eq '2FederateM0re') { throw 'Refusing to store the product default administrator password.' }

if ($DnsNames.Count -lt 1) { throw 'At least one DNS name is required for the runtime certificate.' }
foreach ($name in $DnsNames) {
    if ($name -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$') {
        throw "Runtime certificate DNS name is not a plain lowercase host name: $name"
    }
}
if (($DnsNames | Sort-Object -Unique).Count -ne $DnsNames.Count) { throw 'Runtime certificate DNS names must be distinct.' }

$key = [Security.Cryptography.RSA]::Create(2048)
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$($DnsNames[0]), O=WAI, C=AU", $key,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $subjectAlternativeNames = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    foreach ($name in $DnsNames) { $subjectAlternativeNames.AddDnsName($name) }
    $request.CertificateExtensions.Add($subjectAlternativeNames.Build())
    # A serving leaf, not an authority: it may sign a handshake and nothing else.
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, $true))
    $serverAuthentication = [Security.Cryptography.OidCollection]::new()
    $null = $serverAuthentication.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($serverAuthentication, $true))

    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
    $certificate = $request.CreateSelfSigned($notBefore, $notBefore.AddDays(365))
    try {
        $certificatePEM = $certificate.ExportCertificatePem() + "`n"
        $thumbprint = $certificate.GetCertHashString('SHA256')
    } finally { $certificate.Dispose() }
    $privateKeyPEM = $key.ExportPkcs8PrivateKeyPem() + "`n"
} finally { $key.Dispose() }

if ($certificatePEM -match 'PRIVATE KEY') { throw 'The public certificate must not contain private material.' }

$payloads = @(
    @{ Path = "$basePath/administrator"; Data = @{ 'password' = $administratorPassword } }
    @{ Path = "$basePath/devops"; Data = @{ 'username' = $environment['PING_IDENTITY_DEVOPS_USER']; 'key' = $environment['PING_IDENTITY_DEVOPS_KEY'] } }
    @{ Path = "$basePath/runtime-tls"; Data = @{ 'tls.key' = $privateKeyPEM; 'tls.crt' = $certificatePEM } }
    @{ Path = "$basePath/runtime-ca"; Data = @{ 'ca.pem' = $certificatePEM; 'ca.crt' = $certificatePEM } }
)
Write-Output "Generated a runtime certificate for [$($DnsNames -join ', ')] SHA256=$thumbprint"

if ($ValidateOnly) { Write-Output 'PASS: isolated PingAuthorize inputs are complete and consistent; nothing was written.'; exit 0 }

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
            if (-not $response.IsSuccessStatusCode) {
                $partial = if ($completed) { "$completed earlier path(s) may have new versions" } else { 'no earlier path was written' }
                throw "Vault write failed for $($payload.Path): HTTP $([int]$response.StatusCode); $partial."
            }
        } finally { $response.Dispose(); $request.Dispose() }
        $completed++
    }
} finally { $client.Dispose(); $handler.Dispose() }

Write-Output 'PASS: imported four isolated PingAuthorize records without printing secret values.'
