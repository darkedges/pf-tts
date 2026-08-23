param(
    [string]$EnvFile = '.env.local',
    [int]$HealthTimeoutSeconds = 600,
    [switch]$KeepOnFailure
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$image = 'pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0'

if ($HealthTimeoutSeconds -lt 60 -or $HealthTimeoutSeconds -gt 900) { throw 'Health timeout must be between 60 and 900 seconds.' }
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) { throw 'The ignored local environment file is required.' }
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { throw 'The local environment file contains an invalid entry.' }
    $name = $Matches[1]
    $value = $Matches[2].Trim()
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) { $value = $value.Substring(1, $value.Length - 2) }
    if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) { [Environment]::SetEnvironmentVariable($name, $value, 'Process') }
}
foreach ($required in @('PING_IDENTITY_DEVOPS_USER', 'PING_IDENTITY_DEVOPS_KEY', 'PF_ADMIN_USERNAME', 'PF_ADMIN_PASSWORD')) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($required, 'Process'))) { throw "Missing required local setting: $required." }
}

$randomBytes = [byte[]]::new(8)
[Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
$suffix = ([Convert]::ToHexString($randomBytes)).ToLowerInvariant()
[Array]::Clear($randomBytes, 0, $randomBytes.Length)
$containerName = "wai-pf-clean-$suffix"
$volumeName = "wai-pf-clean-output-$suffix"
$workRoot = Join-Path $root "deploy/pingfederate/generated/clean-bootstrap/$suffix"
$terraformWork = Join-Path $workRoot 'terraform'
$certificatePath = Join-Path $workRoot 'runtime.pem'
$succeeded = $false

function Invoke-Checked([string]$Description, [scriptblock]$Action) {
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "$Description failed." }
}

try {
    [IO.Directory]::CreateDirectory($terraformWork) | Out-Null
    & (Join-Path $PSScriptRoot 'build-pingfederate-profile.ps1')

    Invoke-Checked 'Creating isolated PingFederate volume' { docker volume create $volumeName | Out-Null }
    $profilePath = [IO.Path]::GetFullPath((Join-Path $root 'deploy/pingfederate/profile'))
    $dockerArguments = @(
        'run', '--detach', '--name', $containerName,
        '--publish', '127.0.0.1::9999', '--publish', '127.0.0.1::9031',
        '--tmpfs', '/run/secrets', '--mount', "type=volume,source=$volumeName,target=/opt/out",
        '--mount', "type=bind,source=$profilePath,target=/opt/in,readonly",
        '--env', 'SERVER_PROFILE_URL=https://github.com/pingidentity/pingidentity-server-profiles.git',
        '--env', 'SERVER_PROFILE_PATH=getting-started/pingfederate', '--env', 'SERVER_PROFILE_URL_REDACT=true',
        '--env', 'SERVER_PROFILE_UPDATE=true', '--env', 'PING_IDENTITY_ACCEPT_EULA=YES',
        '--env', 'PING_IDENTITY_DEVOPS_USER', '--env', 'PING_IDENTITY_DEVOPS_KEY',
        '--env', 'PING_IDENTITY_PASSWORD', $image
    )
    $env:PING_IDENTITY_PASSWORD = $env:PF_ADMIN_PASSWORD
    Invoke-Checked 'Starting isolated PingFederate' { docker @dockerArguments | Out-Null }

    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeoutSeconds)
    do {
        $health = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $containerName 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'The isolated PingFederate container disappeared.' }
        if ($health -eq 'healthy') { break }
        if ($health -eq 'unhealthy' -or $health -eq 'exited' -or $health -eq 'dead') { throw "The isolated PingFederate container became $health." }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($health -ne 'healthy') { throw 'Timed out waiting for isolated PingFederate health.' }

    $adminBinding = docker port $containerName 9999/tcp
    $runtimeBinding = docker port $containerName 9031/tcp
    if (@($adminBinding).Count -ne 1 -or @($runtimeBinding).Count -ne 1 -or $adminBinding -notmatch '127\.0\.0\.1:(\d+)$') { throw 'Docker returned ambiguous isolated port bindings.' }
    $adminPort = $Matches[1]
    if ($runtimeBinding -notmatch '127\.0\.0\.1:(\d+)$') { throw 'Docker returned an invalid isolated runtime port binding.' }
    $runtimePort = $Matches[1]

    $certificateReady = $false
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        try {
            & (Join-Path $PSScriptRoot 'export-pf-local-ca.ps1') -Container $containerName -OutputPath $certificatePath
            $certificateReady = $true
            break
        } catch {
            if ($attempt -eq 12) { throw }
            Start-Sleep -Seconds 5
        }
    }
    if (-not $certificateReady) { throw 'The isolated PingFederate certificate did not become valid within 60 seconds.' }
    $env:SSL_CERT_FILE = $certificatePath
    $env:PF_CA_FILE = $certificatePath
    $env:PF_ADMIN_INSECURE = 'false'
    $env:PF_ADMIN_URL = "https://localhost:$adminPort/pf-admin-api/v1"
    $env:PF_TOKEN_ENDPOINT = "https://localhost:$runtimePort/as/token.oauth2"
    $env:PF_JWKS_URL = "https://localhost:$runtimePort/pf/JWKS"
    $env:PINGFEDERATE_PROVIDER_HTTPS_HOST = "https://localhost:$adminPort"
    $env:PINGFEDERATE_PROVIDER_PRODUCT_VERSION = '13.1.0'
    $env:PINGFEDERATE_PROVIDER_USERNAME = $env:PF_ADMIN_USERNAME
    $env:PINGFEDERATE_PROVIDER_PASSWORD = $env:PF_ADMIN_PASSWORD
    $env:PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS = 'false'
    $env:PINGFEDERATE_PROVIDER_CA_CERTIFICATE_PEM_FILES = $certificatePath

    $terraformSource = Join-Path $root 'deploy/pingfederate/terraform'
    Get-ChildItem -LiteralPath $terraformSource -File | Where-Object { $_.Extension -eq '.tf' -or $_.Name -eq 'pf13_1.auto.tfvars.json' } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $terraformWork
    }
    if (-not (Test-Path -LiteralPath (Join-Path $terraformWork 'pf13_1.auto.tfvars.json') -PathType Leaf)) { throw 'The reviewed generated Terraform inputs are required.' }

    & (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/ensure_pf_scope.py')
    if ($LASTEXITCODE -ne 0) { throw 'Isolated OAuth scope provisioning failed.' }
    Invoke-Checked 'Isolated Terraform initialization' { terraform "-chdir=$terraformWork" init -input=false }
    Invoke-Checked 'Isolated Terraform TLS phase' {
        terraform "-chdir=$terraformWork" apply -auto-approve -input=false `
            '-target=pingfederate_keypairs_ssl_server_key.local_runtime' `
            '-target=pingfederate_keypairs_ssl_server_settings.local_runtime'
    }
    $rotatedCertificateReady = $false
    for ($attempt = 1; $attempt -le 18; $attempt++) {
        try {
            & (Join-Path $PSScriptRoot 'export-pf-local-ca.ps1') -Container $containerName -OutputPath $certificatePath
            $rotatedCertificateReady = $true
            break
        } catch {
            if ($attempt -eq 18) { throw }
            Start-Sleep -Seconds 5
        }
    }
    if (-not $rotatedCertificateReady) { throw 'The Terraform-managed PingFederate certificate did not become valid within 90 seconds.' }
    Invoke-Checked 'Isolated Terraform apply' { terraform "-chdir=$terraformWork" apply -auto-approve -input=false }
    $exchangeVerified = $false
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        & (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/verify_live_token_exchange.py')
        if ($LASTEXITCODE -eq 0) { $exchangeVerified = $true; break }
        if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
    }
    if (-not $exchangeVerified) { throw 'Isolated live token-exchange verification did not pass within 60 seconds.' }
    $succeeded = $true
    Write-Output "PASS: clean PingFederate bootstrap completed in isolated container $containerName."
} finally {
    if ($succeeded -or -not $KeepOnFailure) {
        if ($containerName -match '^wai-pf-clean-[0-9a-f]{16}$') { docker rm -f $containerName 2>$null | Out-Null }
        if ($volumeName -match '^wai-pf-clean-output-[0-9a-f]{16}$') { docker volume rm $volumeName 2>$null | Out-Null }
        if ((Test-Path -LiteralPath $workRoot) -and $workRoot.StartsWith((Join-Path $root 'deploy/pingfederate/generated/clean-bootstrap/'), [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force
        }
    } else {
        Write-Warning "Preserved exact failed test resources: $containerName, $volumeName, $workRoot"
    }
}
