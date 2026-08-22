param([string]$EnvFile = '.env.local')

$ErrorActionPreference = 'Stop'
$name = 'TF_VAR_mcp_gateway_client_secret'

if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Environment file not found: $EnvFile"
}

$bytes = [byte[]]::new(48)
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
} finally {
    $rng.Dispose()
}
$secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$lines = [Collections.Generic.List[string]]::new()
$matches = 0
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    if ($line -match "^$([regex]::Escape($name))=") {
        $matches++
        $lines.Add("$name=$secret")
    } else {
        $lines.Add($line)
    }
}
if ($matches -gt 1) {
    throw "Refusing duplicate $name entries in $EnvFile"
}
if ($matches -eq 0) {
    $lines.Add("$name=$secret")
}

$resolved = (Resolve-Path -LiteralPath $EnvFile).Path
$temporary = "$resolved.tmp"
try {
    [IO.File]::WriteAllLines($temporary, $lines, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $resolved -Force
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
    $secret = $null
    [Array]::Clear($bytes, 0, $bytes.Length)
}

Write-Output "$name was generated and stored in the ignored local environment file."
