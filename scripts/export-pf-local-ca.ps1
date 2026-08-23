param(
    [string]$Container = 'wai-pingfederate-13-1',
    [string]$OutputPath = 'deploy/pingfederate/generated/local-runtime-ca.pem',
    [switch]$Trust
)

$ErrorActionPreference = 'Stop'
$ErrorActionPreference = 'Continue'
$raw = '' | docker run --rm -i --network "container:$Container" alpine/openssl s_client -connect localhost:9031 -servername localhost -showcerts 2>&1
$dockerExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($dockerExitCode -ne 0) { throw 'Could not read the PingFederate TLS certificate.' }
$text = $raw -join "`n"
$match = [regex]::Match($text, '-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----')
if (-not $match.Success) { throw 'PingFederate did not return exactly parseable PEM certificate data.' }
if ([regex]::Matches($text, '-----BEGIN CERTIFICATE-----').Count -ne 1) { throw 'PingFederate returned an ambiguous certificate chain.' }

$pem = $match.Value + "`n"
$bytes = [Text.Encoding]::ASCII.GetBytes($pem)
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
try {
    $now = [DateTime]::UtcNow
    if ($cert.NotBefore.ToUniversalTime() -gt $now -or $cert.NotAfter.ToUniversalTime() -le $now) {
        throw 'PingFederate TLS certificate is not currently valid.'
    }
    $san = ($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }).Format($false)
    foreach ($name in @('localhost', 'host.docker.internal')) {
        if ($san -notmatch "DNS Name=$([regex]::Escape($name))(?:,|$)") {
            throw "PingFederate TLS certificate is missing the required $name DNS binding."
        }
    }
    $basicConstraints = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    if ($basicConstraints -and $basicConstraints.CertificateAuthority) {
        throw 'PingFederate returned a CA certificate; refusing broad local trust.'
    }
    if ($cert.Subject -ne $cert.Issuer) {
        throw 'PingFederate local trust requires an exact self-signed runtime leaf.'
    }
} finally {
    $cert.Dispose()
}

$directory = Split-Path -Parent $OutputPath
[IO.Directory]::CreateDirectory((Join-Path (Get-Location) $directory)) | Out-Null
$temporary = "$OutputPath.tmp"
[IO.File]::WriteAllText((Join-Path (Get-Location) $temporary), $pem, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
Write-Output "Exported the validated public PingFederate local trust anchor to $OutputPath."
if ($Trust) {
    & certutil.exe -f -user -addstore Root $OutputPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not trust the PingFederate local runtime certificate.' }
    Write-Output 'Trusted only the validated public PingFederate runtime leaf for the current user.'
}
