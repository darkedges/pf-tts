$ErrorActionPreference = 'Stop'

$raw = docker compose -f deploy/spire/compose.yaml exec -T spire-server /opt/spire/bin/spire-server bundle show -format spiffe
if ($LASTEXITCODE -ne 0) { throw 'Unable to read SPIRE public bundle.' }
$bundle = $raw | ConvertFrom-Json
$jwtKeys = @($bundle.keys | Where-Object { $_.use -eq 'jwt-svid' })
if ($jwtKeys.Count -lt 1) { throw 'SPIRE bundle contains no JWT authorities.' }
$seenKeyIDs = @{}
$verifiedKeys = @()
foreach ($source in $jwtKeys) {
    if ([string]::IsNullOrWhiteSpace($source.kid)) { throw 'SPIRE JWT authority has no key ID.' }
    if ($seenKeyIDs.ContainsKey($source.kid)) { throw "SPIRE JWT authority key ID is ambiguous: $($source.kid)." }
    $seenKeyIDs[$source.kid] = $true
    if ($source.kty -ne 'EC' -or $source.crv -ne 'P-256') { throw 'SPIRE JWT authority must be an EC P-256 key.' }
    if ([string]::IsNullOrWhiteSpace($source.x) -or [string]::IsNullOrWhiteSpace($source.y)) { throw 'SPIRE JWT authority is missing public coordinates.' }
    $verifiedKeys += @{ kty='EC'; crv='P-256'; kid=$source.kid; x=$source.x; y=$source.y; use='sig'; alg='ES256' }
}

$jwks = @{ keys = $verifiedKeys }
$destination = 'deploy/pingfederate/discovered/spire-jwt.jwks.json'
$jwks | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output "Wrote public SPIRE JWT verification bundle to: $destination"
