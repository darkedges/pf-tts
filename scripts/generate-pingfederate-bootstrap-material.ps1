param(
    [string]$OutputPath = 'deploy/pingfederate/profile/env_vars',
    [int]$ValidDays = 7
)

$ErrorActionPreference = 'Stop'
if ($ValidDays -lt 1 -or $ValidDays -gt 30) { throw 'Bootstrap TLS validity must be between 1 and 30 days.' }
$absoluteOutput = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputPath))
$expectedRoot = [IO.Path]::GetFullPath((Join-Path (Get-Location) 'deploy/pingfederate/profile/'))
if (-not $absoluteOutput.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Bootstrap output must stay inside the PingFederate profile overlay.' }
if (Test-Path -LiteralPath $absoluteOutput) { throw 'Refusing to overwrite existing PingFederate bootstrap material.' }

function New-RandomBase64Url([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function New-RandomBase64([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return [Convert]::ToBase64String($bytes)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

$password = New-RandomBase64Url 32
$rsa = [Security.Cryptography.RSA]::Create(2048)
$certificate = $null
$pfx = $null
try {
    $subject = [Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=localhost, O=WAI Local Development')
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $san.AddDnsName('host.docker.internal')
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
        $true
    ))
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays($ValidDays))
    $pfx = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password)
    $fileData = [Convert]::ToBase64String($pfx)
    $currentSystemKey = New-RandomBase64 32
    $pendingSystemKey = New-RandomBase64 32
    $dataStorePassword = New-RandomBase64Url 32

    $lines = @(
        '# Generated local bootstrap material. Contains secrets; never commit.',
        "export dataStores_items_ProvisionerDS_ProvisionerDS_password='$dataStorePassword'",
        "export keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_fileData='$fileData'",
        "export keyPairs_sslServer_items_vtcm75en83g6v1r87ytm7lihi_vtcm75en83g6v1r87ytm7lihi_password='$password'",
        "export serverSettings_systemKeys_items_current_keyData='$currentSystemKey'",
        "export serverSettings_systemKeys_items_pending_keyData='$pendingSystemKey'",
        'export PING_IDENTITY_PASSWORD="${PING_IDENTITY_PASSWORD:?PING_IDENTITY_PASSWORD is required}"'
    )
    [IO.Directory]::CreateDirectory((Split-Path -Parent $absoluteOutput)) | Out-Null
    $temporary = "$absoluteOutput.tmp"
    [IO.File]::WriteAllText($temporary, (($lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $absoluteOutput
} finally {
    if ($null -ne $pfx) { [Array]::Clear($pfx, 0, $pfx.Length) }
    if ($null -ne $certificate) { $certificate.Dispose() }
    $rsa.Dispose()
}
Write-Output "Generated ignored short-lived PingFederate bootstrap material at $OutputPath."
