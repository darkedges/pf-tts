param([string]$EnvFile = '.env.local')

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) { throw "Environment file not found: $EnvFile" }
$lines = [Collections.Generic.List[string]]::new()
$values = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) $EnvFile))) {
    $lines.Add($line)
    if ($line.Trim() -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { $values[$Matches[1]] = $Matches[2] }
}
if (-not $values.ContainsKey('TF_VAR_token_exchange_client_secret') -or [string]::IsNullOrWhiteSpace($values['TF_VAR_token_exchange_client_secret'])) {
    throw 'TF_VAR_token_exchange_client_secret is required; refusing to create an empty client binding.'
}
$desired = [ordered]@{
    PF_JWKS_URL       = 'https://host.docker.internal:9031/pf/JWKS'
    PF_TOKEN_ENDPOINT = 'https://host.docker.internal:9031/as/token.oauth2'
    PF_CLIENT_ID      = 'wai-agent-token-exchange'
    PF_CLIENT_SECRET  = $values['TF_VAR_token_exchange_client_secret']
}
foreach ($entry in $desired.GetEnumerator()) {
    $indexes = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^$([regex]::Escape($entry.Key))=") { $i } })
    if ($indexes.Count -gt 1) { throw "Duplicate $($entry.Key) assignment in $EnvFile." }
    $assignment = "$($entry.Key)=$($entry.Value)"
    if ($indexes.Count -eq 1) { $lines[$indexes[0]] = $assignment } else { $lines.Add($assignment) }
}
$temporary = "$EnvFile.tmp"
[IO.File]::WriteAllLines((Join-Path (Get-Location) $temporary), $lines, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $EnvFile -Force
Write-Output 'Updated local application endpoint and client bindings without printing secret values.'
