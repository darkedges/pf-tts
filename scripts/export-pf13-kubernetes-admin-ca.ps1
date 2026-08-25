param(
    [string]$Namespace = 'wai-pingfederate',
    [string]$Pod = 'wai-pingfederate-0',
    [string]$OutputPath = 'deploy/pingfederate/generated/pf13-kubernetes-admin-ca.pem'
)

$ErrorActionPreference = 'Stop'
if ($Namespace -ne 'wai-pingfederate' -or $Pod -ne 'wai-pingfederate-0') { throw 'Admin trust bootstrap is restricted to the exact isolated PingFederate pod.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
$generated = [IO.Path]::GetFullPath((Join-Path $root 'deploy/pingfederate/generated'))
if (-not $output.StartsWith($generated + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($output) -ne 'pf13-kubernetes-admin-ca.pem') { throw 'The public certificate output must use the bounded ignored generated path.' }

$raw = kubectl exec -n $Namespace $Pod -- /opt/java/bin/keytool -printcert -sslserver localhost:9999 -rfc 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Could not read the isolated private administrator certificate.' }
$matches = [regex]::Matches(($raw -join "`n"), '-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----')
if ($matches.Count -ne 1) { throw 'The isolated administrator endpoint returned an ambiguous certificate chain.' }
$pem = $matches[0].Value + "`n"
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($pem)
try {
    $now = [DateTime]::UtcNow
    if ($cert.NotBefore.ToUniversalTime() -gt $now -or $cert.NotAfter.ToUniversalTime() -le $now) { throw 'Administrator certificate is not currently valid.' }
    $subjectAlternativeName = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($null -eq $subjectAlternativeName) { throw 'Administrator certificate must contain a Subject Alternative Name extension.' }
    if (-not $cert.MatchesHostname('localhost', $true, $true)) { throw 'Administrator certificate is not bound to localhost.' }
    $constraints = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    if ($constraints -and $constraints.CertificateAuthority) { throw 'Refusing to trust a broad CA certificate.' }
    if ($cert.Subject -ne $cert.Issuer) { throw 'Expected one exact self-signed administrator leaf.' }
    $fingerprint = $cert.GetCertHashString('SHA256')
} finally { $cert.Dispose() }

[IO.Directory]::CreateDirectory($generated) | Out-Null
$temporary = "$output.tmp"
[IO.File]::WriteAllText($temporary, $pem, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $output -Force
Write-Output "PASS: captured exact isolated administrator public leaf SHA256=$fingerprint without disabling TLS verification."
