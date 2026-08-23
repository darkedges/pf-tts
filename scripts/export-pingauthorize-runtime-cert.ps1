param(
    [string]$ContainerName = 'pingauthorize-wai',
    [string]$ExpectedDnsName = 'pingauthorize-wai',
    [string]$OutputPath = 'deploy/pingauthorize/generated/runtime-cert.pem'
)

$ErrorActionPreference = 'Stop'

if ($ContainerName -ne 'pingauthorize-wai' -or $ExpectedDnsName -ne 'pingauthorize-wai') {
    throw 'Runtime certificate discovery is restricted to the repository-owned PingAuthorize container identity.'
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$expectedDirectory = [IO.Path]::GetFullPath('deploy/pingauthorize/generated')
if ([IO.Path]::GetDirectoryName($resolvedOutput) -ne $expectedDirectory) {
    throw 'Certificate output must remain in deploy/pingauthorize/generated.'
}
[IO.Directory]::CreateDirectory($expectedDirectory) | Out-Null

& docker exec $ContainerName /opt/java/bin/keytool -printcert -rfc -sslserver localhost:1443 | Set-Content -LiteralPath $resolvedOutput -Encoding ascii
if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve the PingAuthorize runtime public certificate.' }

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
if ($sanText -notmatch "DNS Name=$([regex]::Escape($ExpectedDnsName))(,|$|\r|\n)") {
    throw "PingAuthorize certificate is not bound to the expected service DNS name $ExpectedDnsName."
}

Write-Output "Validated PingAuthorize runtime public certificate for $ExpectedDnsName`: $($cert.Thumbprint)"
