<#
.SYNOPSIS
Private Terraform configuration channel for the isolated Kubernetes
PingFederate 13.1 logical TTS.

.DESCRIPTION
Task 53 permits configuration of the isolated logical TTS only through a bounded
private administrative channel, and only after the reachable runtime proves it
is exactly PingFederate 13.1 with the reviewed plugin classes installed.

This gate:

  * refuses any namespace, release, or pod other than the reviewed isolated one,
  * opens a bounded loopback port-forward to port 9999 and never creates an
    administrator Ingress,
  * verifies the administrator TLS leaf against the exported admin CA,
  * reads the administrator credential and every OAuth client secret from the
    exact Vault-synchronized Kubernetes Secrets into process environment only,
  * attests exact version 13.1 and the reviewed plugin classes before plan or
    apply,
  * keeps the Kubernetes state separate from the Docker harness state, and
  * never passes a credential as a command-line argument, never echoes a secret,
    and never blocks on an interactive prompt.

Apply consumes a previously saved plan, so an unreviewed diff can never be
applied and Terraform can never hang waiting for a confirmation that no operator
is present to give.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('init', 'validate', 'plan', 'apply', 'update-browser')]
    [string]$Command,
    [string]$Namespace = 'wai-pingfederate',
    [string]$Release = 'wai-pingfederate',
    [string]$Pod = 'wai-pingfederate-0',
    [string]$SpireNamespace = 'spire-system',
    [string]$SpireServerPod = 'spire-server-0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Namespace -ne 'wai-pingfederate' -or $Release -ne 'wai-pingfederate' -or $Pod -ne 'wai-pingfederate-0') {
    throw 'This gate is restricted to the exact isolated PingFederate 13.1 release.'
}
foreach ($required in @('kubectl', 'terraform', 'python')) {
    if (-not (Get-Command $required -ErrorAction SilentlyContinue)) { throw "$required is required." }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$terraformDir = Join-Path $repoRoot 'deploy/pingfederate/terraform'
$generatedDir = Join-Path $repoRoot 'deploy/pingfederate/generated'
$statePath = Join-Path $generatedDir 'pf13-kubernetes.tfstate'
$planPath = Join-Path $generatedDir 'pf13-kubernetes.tfplan'
$varFile = Join-Path $terraformDir 'kubernetes.tfvars'
$adminCa = Join-Path $generatedDir 'pf13-kubernetes-admin-ca.pem'

if (-not (Test-Path -LiteralPath $varFile -PathType Leaf)) { throw 'The reviewed Kubernetes variable file is missing.' }
if (-not (Test-Path -LiteralPath $adminCa -PathType Leaf)) {
    throw 'Export the isolated administrator CA first: make pf13-k8s-export-admin-ca.'
}
if ($Command -ne 'init' -and -not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'The isolated Kubernetes Terraform state is missing. Refusing to fall back to the Docker harness state.'
}
if ($Command -eq 'apply' -and -not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
    throw 'No saved plan is present. Run plan and review it before apply.'
}

function Read-SecretValue {
    param([string]$Secret, [string]$Key)
    $encoded = kubectl -n $Namespace get secret $Secret -o "jsonpath={.data.$Key}"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($encoded)) {
        throw "Could not read the exact field $Key from Secret $Secret."
    }
    $value = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Secret $Secret field $Key is empty." }
    return $value
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$forward = $null
$exit = 1
$managed = @(
    'PINGFEDERATE_PROVIDER_HTTPS_HOST', 'PINGFEDERATE_PROVIDER_ADMIN_API_PATH',
    'PINGFEDERATE_PROVIDER_USERNAME', 'PINGFEDERATE_PROVIDER_PASSWORD',
    'PINGFEDERATE_PROVIDER_PRODUCT_VERSION', 'PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS',
    'PINGFEDERATE_PROVIDER_CA_CERTIFICATE_PEM_FILES',
    'PF_ADMIN_URL', 'PF_ADMIN_USERNAME', 'PF_ADMIN_PASSWORD', 'PF_ADMIN_INSECURE', 'SSL_CERT_FILE',
    'PF_TRANSACTION_SCOPE',
    'TF_VAR_token_exchange_client_secret', 'TF_VAR_browser_client_secret',
    'TF_VAR_mcp_gateway_client_secret', 'TF_VAR_lab_user_client_secret', 'TF_VAR_lab_user_password',
    'TF_VAR_spire_jwks'
)

try {
    $forward = Start-Process kubectl -WindowStyle Hidden -PassThru -ArgumentList @(
        '-n', $Namespace, 'port-forward', '--address', '127.0.0.1', "pod/$Pod", "${port}:9999")
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($forward.HasExited) { throw 'Private port-forward exited before configuration.' }
        try {
            $probe = [Net.Sockets.TcpClient]::new()
            $probe.Connect('127.0.0.1', $port)
            $probe.Dispose()
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) { throw 'Private port-forward did not become ready.' }

    $username = Read-SecretValue -Secret 'wai-pf13-administrator' -Key 'username'
    if ($username -ne 'administrator') { throw 'Administrator secret does not match the reviewed account contract.' }

    $env:PF_ADMIN_USERNAME = $username
    $env:PF_ADMIN_PASSWORD = Read-SecretValue -Secret 'wai-pf13-administrator' -Key 'password'
    $env:PF_ADMIN_URL = "https://localhost:$port/pf-admin-api/v1"
    $env:PF_ADMIN_INSECURE = 'false'
    $env:SSL_CERT_FILE = $adminCa

    python (Join-Path $repoRoot 'deploy/pingfederate/scripts/attest_pf13_runtime.py')
    if ($LASTEXITCODE -ne 0) { throw 'Runtime attestation failed. Refusing to configure the isolated logical TTS.' }

    # PingFederate rejects an OAuth client that restricts an undefined scope, and
    # Terraform does not own the OAuth server's scope collection. Provision the
    # two approved fixed scopes first. The helper is create-only, refuses any
    # scope outside the reviewed allowlist, and preserves unrelated settings.
    if ($Command -in @('plan', 'apply', 'update-browser')) {
        foreach ($scope in @('mcp:invoke', 'mcp.system.whoami')) {
            $env:PF_TRANSACTION_SCOPE = $scope
            python (Join-Path $repoRoot 'deploy/pingfederate/scripts/ensure_pf_scope.py')
            if ($LASTEXITCODE -ne 0) { throw "Could not provision the approved OAuth scope $scope." }
        }
        Remove-Item Env:PF_TRANSACTION_SCOPE -ErrorAction SilentlyContinue
    }

    $env:PINGFEDERATE_PROVIDER_HTTPS_HOST = "https://localhost:$port"
    $env:PINGFEDERATE_PROVIDER_ADMIN_API_PATH = '/pf-admin-api/v1'
    $env:PINGFEDERATE_PROVIDER_USERNAME = $env:PF_ADMIN_USERNAME
    $env:PINGFEDERATE_PROVIDER_PASSWORD = $env:PF_ADMIN_PASSWORD
    $env:PINGFEDERATE_PROVIDER_PRODUCT_VERSION = '13.1.0'
    $env:PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS = 'false'
    $env:PINGFEDERATE_PROVIDER_CA_CERTIFICATE_PEM_FILES = $adminCa

    # The actor token processor must trust exactly the SPIRE server that attests
    # the workloads in this cluster. Reading the bundle from that server means the
    # isolated logical TTS can never inherit another environment's trust domain
    # keys, and a rotated JWT authority is picked up by re-running this gate.
    $bundle = kubectl -n $SpireNamespace exec $SpireServerPod -c spire-server -- spire-server bundle show -format spiffe
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($bundle)) { throw 'Could not read the in-cluster SPIRE trust bundle.' }
    $jwtKeys = @(($bundle | ConvertFrom-Json).keys | Where-Object { $_.use -eq 'jwt-svid' })
    if ($jwtKeys.Count -eq 0) { throw 'The SPIRE trust bundle contains no JWT-SVID signing key.' }
    # SPIRE marks its JWT authorities `use: jwt-svid`, which is not the JWK value a
    # verification-key selector looks for, and its X.509 authorities carry no key
    # ID at all. Translate each JWT authority into an exact public verification key
    # the reviewed processor can select, copying only public material and pinning
    # the algorithm rather than letting a token header choose one.
    $seen = @{}
    $trusted = @()
    foreach ($source in $jwtKeys) {
        if ([string]::IsNullOrWhiteSpace($source.kid)) { throw 'A SPIRE JWT authority has no key ID. Refusing an ambiguous trust anchor.' }
        if ($seen.ContainsKey($source.kid)) { throw "SPIRE JWT authority key ID is ambiguous: $($source.kid)." }
        $seen[$source.kid] = $true
        switch ($source.kty) {
            'RSA' {
                if ([string]::IsNullOrWhiteSpace($source.n) -or [string]::IsNullOrWhiteSpace($source.e)) { throw 'A SPIRE RSA JWT authority is missing public material.' }
                $trusted += [ordered]@{ kty = 'RSA'; kid = $source.kid; n = $source.n; e = $source.e; use = 'sig'; alg = 'RS256' }
            }
            'EC' {
                if ($source.crv -ne 'P-256') { throw 'A SPIRE EC JWT authority is not on the reviewed P-256 curve.' }
                if ([string]::IsNullOrWhiteSpace($source.x) -or [string]::IsNullOrWhiteSpace($source.y)) { throw 'A SPIRE EC JWT authority is missing public coordinates.' }
                $trusted += [ordered]@{ kty = 'EC'; crv = 'P-256'; kid = $source.kid; x = $source.x; y = $source.y; use = 'sig'; alg = 'ES256' }
            }
            default { throw "SPIRE JWT authority key type $($source.kty) is outside the reviewed RS256/ES256 allowlist." }
        }
    }
    $env:TF_VAR_spire_jwks = (@{ keys = $trusted } | ConvertTo-Json -Depth 6 -Compress)
    Write-Output "Trusting $($trusted.Count) in-cluster SPIRE JWT-SVID signing key(s)."

    $env:TF_VAR_token_exchange_client_secret = Read-SecretValue -Secret 'wai-pf13-oauth-token-exchange' -Key 'client-secret'
    $env:TF_VAR_browser_client_secret = Read-SecretValue -Secret 'wai-pf13-oauth-browser' -Key 'client-secret'
    $env:TF_VAR_mcp_gateway_client_secret = Read-SecretValue -Secret 'wai-pf13-oauth-mcp-gateway' -Key 'client-secret'
    $env:TF_VAR_lab_user_client_secret = Read-SecretValue -Secret 'wai-pf13-oauth-lab-user' -Key 'client-secret'
    $env:TF_VAR_lab_user_password = Read-SecretValue -Secret 'wai-pf13-oauth-lab-user' -Key 'user-password'

    $chdir = "-chdir=$terraformDir"
    switch ($Command) {
        'init' {
            & terraform $chdir init -input=false
        }
        'validate' {
            & terraform $chdir validate
        }
        'plan' {
            & terraform $chdir plan -input=false -lock-timeout=60s "-state=$statePath" "-var-file=$varFile" "-out=$planPath"
        }
        'apply' {
            & terraform $chdir apply -input=false -lock-timeout=60s "-state=$statePath" $planPath
        }
        'update-browser' {
            # Isolate the reviewed browser client from unrelated provider or
            # plugin normalization drift. This target must never include token
            # processors, the TEPP, the ATM, or signing keys.
            & terraform $chdir plan -input=false -lock-timeout=60s "-state=$statePath" "-var-file=$varFile" '-target=pingfederate_oauth_client.browser' "-out=$planPath"
            if ($LASTEXITCODE -ne 0) { throw 'Targeted browser client plan failed.' }
            & terraform $chdir apply -input=false -lock-timeout=60s "-state=$statePath" $planPath
        }
    }
    $exit = $LASTEXITCODE
} finally {
    foreach ($name in $managed) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    if ($null -ne $forward -and -not $forward.HasExited) { Stop-Process -Id $forward.Id -Force }
}

if ($exit -ne 0) { throw "terraform $Command failed against the isolated Kubernetes runtime." }
Write-Output "PASS: completed terraform $Command against the attested isolated PingFederate 13.1 runtime."
