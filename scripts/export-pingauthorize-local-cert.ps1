param(
    [string]$HostName = 'localhost',
    [int]$Port = 9444,
    [string]$OutputPath = 'deploy/pingauthorize/generated/pap-cert.pem',
    [switch]$Trust
)

$ErrorActionPreference = 'Stop'
if ($HostName -ne 'localhost' -or $Port -lt 1 -or $Port -gt 65535) {
    throw 'Local PingAuthorize certificate discovery is restricted to localhost.'
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$expectedDirectory = [IO.Path]::GetFullPath('deploy/pingauthorize/generated')
if ([IO.Path]::GetDirectoryName($resolvedOutput) -ne $expectedDirectory) {
    throw 'Certificate output must remain in deploy/pingauthorize/generated.'
}
[IO.Directory]::CreateDirectory($expectedDirectory) | Out-Null

& docker exec pingauthorizepap sh -c 'keytool -printcert -rfc -sslserver localhost:1443 > /tmp/pap-cert.pem'
if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve the Policy Editor public certificate.' }
& docker cp 'pingauthorizepap:/tmp/pap-cert.pem' $resolvedOutput
if ($LASTEXITCODE -ne 0) { throw 'Could not copy the Policy Editor public certificate.' }

$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedOutput)
if ($null -eq $cert -or $cert.HasPrivateKey) {
    throw 'PingAuthorize did not present a public certificate.'
}
if ($cert.Subject -ne $cert.Issuer) {
    throw 'Expected the local development certificate to be self-signed.'
}
$now = [DateTimeOffset]::UtcNow
if ($now -lt $cert.NotBefore.ToUniversalTime() -or $now -ge $cert.NotAfter.ToUniversalTime()) {
    throw 'PingAuthorize presented a certificate outside its validity period.'
}
$san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
if ($null -eq $san) {
    throw 'PingAuthorize certificate has no subject alternative name extension.'
}
$sanText = $san.Format($false)
if ($sanText -notmatch 'DNS Name=localhost' -or $sanText -notmatch 'IP Address=127\.0\.0\.1') {
    throw 'PingAuthorize certificate is not bound to localhost and loopback.'
}

if ($Trust) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
    $store.Open('ReadWrite')
    try {
        if ($store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false).Count -eq 0) {
            $store.Add($cert)
        }
    } finally {
        $store.Close()
    }
}

Write-Output "Validated local PingAuthorize public certificate: $($cert.Thumbprint)"
