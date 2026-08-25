param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('init', 'fmt', 'validate', 'plan', 'apply', 'replace-client', 'update-browser')]
    [string]$Command,
    [string]$EnvFile = '.env.local'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) { throw "Environment file not found: $EnvFile" }
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { throw "Invalid environment assignment in $EnvFile" }
    $name = $Matches[1]; $value = $Matches[2].Trim()
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) {
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

$admin = $null
if (-not [Uri]::TryCreate($env:PF_ADMIN_URL, [UriKind]::Absolute, [ref]$admin) -or
    $admin.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($admin.Host)) {
    throw 'PF_ADMIN_URL must be an absolute HTTPS URL.'
}
if ([string]::IsNullOrWhiteSpace($env:PF_ADMIN_USERNAME) -or [string]::IsNullOrWhiteSpace($env:PF_ADMIN_PASSWORD)) {
    throw 'PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD are required.'
}

$env:PINGFEDERATE_PROVIDER_HTTPS_HOST = $admin.GetLeftPart([UriPartial]::Authority)
$env:PINGFEDERATE_PROVIDER_PRODUCT_VERSION = '13.1.0'
$env:PINGFEDERATE_PROVIDER_USERNAME = $env:PF_ADMIN_USERNAME
$env:PINGFEDERATE_PROVIDER_PASSWORD = $env:PF_ADMIN_PASSWORD
$env:PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS = if ($env:PF_ADMIN_INSECURE -eq 'true') { 'true' } else { 'false' }

if ($Command -eq 'replace-client') {
    & terraform '-chdir=deploy/pingfederate/terraform' apply '-replace=pingfederate_oauth_client.token_exchange'
} elseif ($Command -eq 'update-browser') {
    # Isolate the browser redirect update from unrelated provider/plugin
    # normalization drift. This target must never include token resources.
    & terraform '-chdir=deploy/pingfederate/terraform' apply '-target=pingfederate_oauth_client.browser'
} else {
    & terraform '-chdir=deploy/pingfederate/terraform' $Command
}
exit $LASTEXITCODE
