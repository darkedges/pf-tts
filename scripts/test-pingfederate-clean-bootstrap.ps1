param(
    [string]$EnvFile = '.env.local',
    [int]$HealthTimeoutSeconds = 600,
    [switch]$KeepOnFailure,
    [switch]$ProbeTransactionTokens,
    [switch]$TestTransactionTokensInnerProfile,
    [switch]$TestTTSAdapter,
    [switch]$TestStrictCallChain
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$image = 'pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0'

if ($HealthTimeoutSeconds -lt 60 -or $HealthTimeoutSeconds -gt 900) { throw 'Health timeout must be between 60 and 900 seconds.' }
$strictInnerProfile = $TestTransactionTokensInnerProfile -or $TestTTSAdapter -or $TestStrictCallChain
if ($ProbeTransactionTokens -and $strictInnerProfile) { throw 'Select only one isolated Transaction Tokens gate.' }
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
$adapterContainer = "wai-tts-adapter-$suffix"
$adapterImage = "wai-tts-adapter-gate:$suffix"
$probeImage = "wai-tts-probe-gate:$suffix"
$strictNetwork = "wai-tts-chain-$suffix"
$strictGatewayContainer = "wai-strict-gateway-$suffix"
$strictMCPContainer = "wai-strict-mcp-$suffix"
$strictAPIContainer = "wai-strict-api-$suffix"
$strictGatewayImage = "wai-strict-gateway-gate:$suffix"
$strictMCPImage = "wai-strict-mcp-gate:$suffix"
$strictAPIImage = "wai-strict-api-gate:$suffix"
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

	$env:PF_TRANSACTION_SCOPE = 'mcp:invoke'
    & (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/ensure_pf_scope.py')
    if ($LASTEXITCODE -ne 0) { throw 'Isolated OAuth scope provisioning failed.' }
	if ($strictInnerProfile) {
		$env:PF_TRANSACTION_SCOPE = 'mcp.system.whoami'
		& (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/ensure_pf_scope.py')
		if ($LASTEXITCODE -ne 0) { throw 'Isolated strict Transaction Token scope provisioning failed.' }
	}
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
    $applyArguments = @("-chdir=$terraformWork", 'apply', '-auto-approve', '-input=false')
    if ($ProbeTransactionTokens) { $applyArguments += '-var=enable_transaction_tokens_capability_probe=true' }
    if ($strictInnerProfile) {
        $applyArguments += '-var=enable_transaction_tokens_capability_probe=true'
        $applyArguments += '-var=enable_transaction_tokens_inner_profile=true'
    }
    Invoke-Checked 'Isolated Terraform apply' { terraform @applyArguments }
    if ($strictInnerProfile) { $env:PF_EXPECT_TRANSACTION_TOKEN_INNER_PROFILE = 'true' }
    $exchangeVerified = $false
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        & (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/verify_live_token_exchange.py')
        if ($LASTEXITCODE -eq 0) { $exchangeVerified = $true; break }
        if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
    }
    if (-not $exchangeVerified) { throw 'Isolated live token-exchange verification did not pass within 60 seconds.' }
    if ($ProbeTransactionTokens) {
        $env:PF_CAPABILITY_ISOLATED_CONTAINER = $containerName
        & (Join-Path $PSScriptRoot 'run-python.ps1') -ScriptPath (Join-Path $root 'deploy/pingfederate/scripts/probe_transaction_tokens_capabilities.py')
        if ($LASTEXITCODE -ne 0) { throw 'Isolated Transaction Tokens capability probe failed.' }
    }
    if ($TestTTSAdapter -or $TestStrictCallChain) {
        Invoke-Checked 'Registering isolated TTS adapter SPIFFE identity' {
            Push-Location $root
            try {
                bash scripts/spire-register.sh
            }
            finally {
                Pop-Location
            }
        }
        $socketVolume = [Environment]::GetEnvironmentVariable('SPIRE_SOCKET_VOLUME', 'Process')
        if ([string]::IsNullOrWhiteSpace($socketVolume)) { $socketVolume = 'spire_spire-agent-socket' }
        if ($socketVolume -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$') { throw 'SPIRE socket volume name is invalid.' }
        Invoke-Checked 'Building isolated TTS adapter image' { docker build --build-arg COMMAND=tts-adapter --tag $adapterImage $root }
        Invoke-Checked 'Building isolated TTS probe image' { docker build --build-arg COMMAND=tts-probe --tag $probeImage $root }
        $internalTokenEndpoint = "https://host.docker.internal:$runtimePort/as/token.oauth2"
        $internalJWKS = "https://host.docker.internal:$runtimePort/pf/JWKS"
        if (-not $env:PF_CLIENT_ID) { $env:PF_CLIENT_ID = 'wai-agent-token-exchange' }
        if (-not $env:PF_CLIENT_SECRET) { $env:PF_CLIENT_SECRET = $env:TF_VAR_token_exchange_client_secret }
        $adapterArguments = @(
            'run', '--detach', '--name', $adapterContainer,
            '--label', 'wai.workload=tts-adapter', '--publish', '127.0.0.1::8448',
            '--mount', "type=volume,source=$socketVolume,target=/run/spire/sockets,readonly",
            '--mount', "type=bind,source=$certificatePath,target=/run/pingfederate/ca.pem,readonly",
            '--env', 'SPIFFE_ENDPOINT=unix:///run/spire/sockets/agent.sock',
            '--env', "PF_TOKEN_ENDPOINT=$internalTokenEndpoint", '--env', "PF_JWKS_URL=$internalJWKS",
            '--env', 'PF_TRANSACTION_ISSUER', '--env', 'PF_CLIENT_ID', '--env', 'PF_CLIENT_SECRET',
            '--env', 'PF_CA_FILE=/run/pingfederate/ca.pem', $adapterImage
        )
        Invoke-Checked 'Starting isolated TTS adapter' { docker @adapterArguments | Out-Null }
        $adapterBinding = docker port $adapterContainer 8448/tcp
        if (@($adapterBinding).Count -ne 1 -or $adapterBinding -notmatch '127\.0\.0\.1:(\d+)$') { throw 'Docker returned an invalid isolated adapter port binding.' }
        $adapterPort = $Matches[1]
        if ($TestStrictCallChain) {
            $policyPath = [IO.Path]::GetFullPath((Join-Path $root 'config/authorization-strict.rego'))
            Invoke-Checked 'Creating isolated strict Call Chain network' { docker network create $strictNetwork | Out-Null }
            Invoke-Checked 'Building isolated strict gateway image' { docker build --build-arg COMMAND=strict-mcp-gateway --tag $strictGatewayImage $root }
            Invoke-Checked 'Building isolated strict MCP image' { docker build --build-arg COMMAND=strict-demo-mcp-server --tag $strictMCPImage $root }
            Invoke-Checked 'Building isolated strict API image' { docker build --build-arg COMMAND=strict-demo-api --tag $strictAPIImage $root }
            $strictCommon = @(
                '--network', $strictNetwork,
                '--mount', "type=volume,source=$socketVolume,target=/run/spire/sockets,readonly",
                '--mount', "type=bind,source=$certificatePath,target=/run/pingfederate/ca.pem,readonly",
                '--env', 'SPIFFE_ENDPOINT=unix:///run/spire/sockets/agent.sock',
                '--env', "PF_JWKS_URL=$internalJWKS", '--env', 'PF_TRANSACTION_ISSUER',
                '--env', 'PF_CA_FILE=/run/pingfederate/ca.pem'
            )
            Invoke-Checked 'Starting isolated strict API' {
                docker run --detach --name $strictAPIContainer --label 'wai.workload=strict-demo-api' @strictCommon $strictAPIImage | Out-Null
            }
            Invoke-Checked 'Starting isolated strict MCP server' {
                docker run --detach --name $strictMCPContainer --label 'wai.workload=strict-demo-mcp-server' @strictCommon --env "STRICT_DEMO_API_URL=https://${strictAPIContainer}:8545" $strictMCPImage | Out-Null
            }
            Invoke-Checked 'Starting isolated strict gateway' {
                docker run --detach --name $strictGatewayContainer --label 'wai.workload=strict-mcp-gateway' @strictCommon --mount "type=bind,source=$policyPath,target=/run/wai/authorization.rego,readonly" --env "STRICT_MCP_SERVER_URL=https://${strictMCPContainer}:8544" $strictGatewayImage | Out-Null
            }
        }
        $probeCommon = @(
            'run', '--rm', '--mount', "type=volume,source=$socketVolume,target=/run/spire/sockets,readonly",
            '--mount', "type=bind,source=$certificatePath,target=/run/pingfederate/ca.pem,readonly",
            '--env', 'SPIFFE_ENDPOINT=unix:///run/spire/sockets/agent.sock',
            '--env', "TTS_ADAPTER_URL=https://host.docker.internal:$adapterPort/as/token.oauth2",
            '--env', "PF_TOKEN_ENDPOINT=$internalTokenEndpoint", '--env', "PF_JWKS_URL=$internalJWKS",
            '--env', 'PF_TRANSACTION_ISSUER', '--env', 'PF_CA_FILE=/run/pingfederate/ca.pem',
            '--env', 'TF_VAR_lab_user_name', '--env', 'TF_VAR_lab_user_password',
            '--env', 'TF_VAR_lab_user_client_id', '--env', 'TF_VAR_lab_user_client_secret'
        )
        if ($TestStrictCallChain) {
            $probeCommon += @('--network', $strictNetwork, '--env', "STRICT_MCP_GATEWAY_URL=https://${strictGatewayContainer}:8543")
        }
        $approved = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            $approvedOutput = & docker @probeCommon --label 'wai.workload=demo-agent' --env 'PROBE_SPIFFE_ID=spiffe://example.org/agent/demo' $probeImage 2>&1
            if ($LASTEXITCODE -eq 0) { $approved = $true; break }
            if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
        }
        if (-not $approved) { throw 'Approved SPIFFE requester probe failed.' }
		$bearerRejectedOutput = @()
		$strictTLSRejectedOutput = @()
		if ($TestStrictCallChain) {
			$bearerRejectedOutput = & docker @probeCommon --label 'wai.workload=demo-agent' --env 'PROBE_SPIFFE_ID=spiffe://example.org/agent/demo' --env 'EXPECT_STRICT_BEARER_REJECTION=true' $probeImage 2>&1
			if ($LASTEXITCODE -ne 0) { throw 'Legacy Bearer transport rejection probe failed.' }
			$strictTLSRejectedOutput = & docker @probeCommon --label 'wai.workload=strict-demo-mcp-server' --env 'PROBE_SPIFFE_ID=spiffe://example.org/mcp/demo-strict' --env 'EXPECT_STRICT_TLS_REJECTION=true' $probeImage 2>&1
			if ($LASTEXITCODE -ne 0) { throw 'Strict gateway wrong-workload mTLS rejection probe failed.' }
		}
        $rejectedOutput = & docker @probeCommon --label 'wai.workload=mcp-gateway' --env 'PROBE_SPIFFE_ID=spiffe://example.org/gateway/mcp' --env 'EXPECT_REJECTION=true' $probeImage 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Wrong-workload SPIFFE rejection probe failed.' }
        $adapterLogs = docker logs $adapterContainer 2>&1
        $strictLogs = @()
        if ($TestStrictCallChain) {
            $strictLogs += docker logs $strictGatewayContainer 2>&1
            $strictLogs += docker logs $strictMCPContainer 2>&1
            $strictLogs += docker logs $strictAPIContainer 2>&1
        }
        $captured = (@($approvedOutput) + @($bearerRejectedOutput) + @($strictTLSRejectedOutput) + @($rejectedOutput) + @($adapterLogs) + @($strictLogs)) -join "`n"
        $credentialLeak = @($env:PF_CLIENT_SECRET, $env:TF_VAR_lab_user_password) | Where-Object { $_ -and $captured.Contains($_) }
        if ($captured -match 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.' -or $captured -match '(?i)Authorization\s*[:=]' -or $credentialLeak.Count -gt 0) {
            throw 'Isolated TTS adapter output contained prohibited credential-shaped material.'
        }
        Write-Output 'PASS: isolated TTS adapter accepted the approved SPIFFE requester, rejected the wrong workload, returned exact outer semantics, and emitted no token-shaped output.'
        if ($TestStrictCallChain) { Write-Output 'PASS: isolated strict Transaction Token Call Chain completed with bounded token-free output.' }
    }
    $succeeded = $true
    Write-Output "PASS: clean PingFederate bootstrap completed in isolated container $containerName."
} finally {
    if ($succeeded -or -not $KeepOnFailure) {
        foreach ($strictContainer in @($strictGatewayContainer, $strictMCPContainer, $strictAPIContainer)) {
            if ($strictContainer -match '^wai-strict-(gateway|mcp|api)-[0-9a-f]{16}$') { docker rm -f $strictContainer 2>$null | Out-Null }
        }
        foreach ($strictImage in @($strictGatewayImage, $strictMCPImage, $strictAPIImage)) {
            if ($strictImage -match '^wai-strict-(gateway|mcp|api)-gate:[0-9a-f]{16}$') { docker image rm $strictImage 2>$null | Out-Null }
        }
        if ($strictNetwork -match '^wai-tts-chain-[0-9a-f]{16}$') { docker network rm $strictNetwork 2>$null | Out-Null }
        if ($adapterContainer -match '^wai-tts-adapter-[0-9a-f]{16}$') { docker rm -f $adapterContainer 2>$null | Out-Null }
        if ($adapterImage -match '^wai-tts-adapter-gate:[0-9a-f]{16}$') { docker image rm $adapterImage 2>$null | Out-Null }
        if ($probeImage -match '^wai-tts-probe-gate:[0-9a-f]{16}$') { docker image rm $probeImage 2>$null | Out-Null }
        if ($containerName -match '^wai-pf-clean-[0-9a-f]{16}$') { docker rm -f $containerName 2>$null | Out-Null }
        if ($volumeName -match '^wai-pf-clean-output-[0-9a-f]{16}$') { docker volume rm $volumeName 2>$null | Out-Null }
        if ((Test-Path -LiteralPath $workRoot) -and $workRoot.StartsWith((Join-Path $root 'deploy/pingfederate/generated/clean-bootstrap/'), [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force
        }
    } else {
        Write-Warning "Preserved exact failed test resources: $containerName, $volumeName, $workRoot"
    }
}
