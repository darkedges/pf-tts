param(
    [string]$VaultAddress = 'https://vault.internal.darkedges.com'
)

$ErrorActionPreference = 'Stop'
if ($VaultAddress -ne 'https://vault.internal.darkedges.com') { throw 'VaultAddress must be the reviewed HTTPS Vault origin.' }
if ([Environment]::GetEnvironmentVariable('VAULT_SKIP_VERIFY', 'Process') -match '^(?i:true|1)$') { throw 'Vault TLS verification must not be disabled.' }
if (-not (Get-Command vault -ErrorAction SilentlyContinue)) { throw 'Vault CLI is required.' }

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$policy = [IO.Path]::GetFullPath((Join-Path $root 'deploy/vault/wai-strict-policy.hcl'))
if (-not (Test-Path -LiteralPath $policy -PathType Leaf) -or (Get-Item -LiteralPath $policy -Force).LinkType) { throw 'Reviewed Vault policy is missing or is a symbolic link.' }
$policyText = [IO.File]::ReadAllText($policy)
foreach ($required in @('kv/data/wai/pingfederate-13-1/runtime-ca', 'kv/data/wai/pingfederate-13-1/oauth/token-exchange', 'kv/data/wai/workbench')) {
    if (-not $policyText.Contains($required)) { throw "Reviewed Vault policy is missing $required." }
}
if ($policyText.Contains('*') -or $policyText -match 'capabilities\s*=\s*\[[^\]]*(create|update|delete|sudo)') { throw 'Vault runtime policy must be exact-path read-only.' }

$env:VAULT_ADDR = $VaultAddress
& vault policy write wai-strict $policy
if ($LASTEXITCODE -ne 0) { throw 'Failed to install the wai-strict read-only policy.' }
& vault write auth/kubernetes/role/wai-strict `
    bound_service_account_names=wai-vault-auth `
    bound_service_account_namespaces=wai-strict `
    audience=vault `
    token_policies=wai-strict `
    token_ttl=10m `
    token_max_ttl=30m
if ($LASTEXITCODE -ne 0) { throw 'Failed to install the exact wai-strict Kubernetes auth role.' }

Write-Output 'PASS: configured the exact wai-strict Vault policy and Kubernetes auth role.'
