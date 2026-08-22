$ErrorActionPreference = 'Stop'

$raw = docker compose -f deploy/spire/compose.yaml exec -T spire-server /opt/spire/bin/spire-server bundle show -format spiffe
if ($LASTEXITCODE -ne 0) { throw 'Unable to read SPIRE public bundle.' }
$bundle = $raw | ConvertFrom-Json
$jwtKeys = @($bundle.keys | Where-Object { $_.use -eq 'jwt-svid' })
if ($jwtKeys.Count -ne 1) { throw "Expected exactly one SPIRE JWT authority; found $($jwtKeys.Count)." }
$source = $jwtKeys[0]
if ([string]::IsNullOrWhiteSpace($source.kid)) { throw 'SPIRE JWT authority has no key ID.' }
if ($source.kty -ne 'EC' -or $source.crv -ne 'P-256') { throw 'SPIRE JWT authority must be an EC P-256 key.' }
if ([string]::IsNullOrWhiteSpace($source.x) -or [string]::IsNullOrWhiteSpace($source.y)) { throw 'SPIRE JWT authority is missing public coordinates.' }

$jwks = @{ keys = @(@{ kty='EC'; crv='P-256'; kid=$source.kid; x=$source.x; y=$source.y; use='sig'; alg='ES256' }) }
$destination = 'deploy/pingfederate/discovered/spire-jwt.jwks.json'
$jwks | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output "Wrote public SPIRE JWT verification bundle to: $destination"
