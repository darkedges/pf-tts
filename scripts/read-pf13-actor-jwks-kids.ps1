<#
.SYNOPSIS
Print the SPIRE JWT authority key IDs the actor token processor currently trusts.

.DESCRIPTION
Opens a bounded loopback port-forward to the private administrator API, reads the
reviewed actor token processor, and prints one key ID per line. It prints key
identifiers only: no key material, no credential, and no response body.
#>
param(
    [string]$Namespace = 'wai-pingfederate',
    [string]$Pod = 'wai-pingfederate-0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Namespace -ne 'wai-pingfederate' -or $Pod -ne 'wai-pingfederate-0') {
    throw 'This reader is restricted to the exact isolated PingFederate release.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$adminCa = Join-Path $repoRoot 'deploy/pingfederate/generated/pf13-kubernetes-admin-ca.pem'
if (-not (Test-Path -LiteralPath $adminCa -PathType Leaf)) { throw 'Export the isolated administrator CA first: make pf13-k8s-export-admin-ca.' }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$forward = $null
try {
    $forward = Start-Process kubectl -WindowStyle Hidden -PassThru -ArgumentList @(
        '-n', $Namespace, 'port-forward', '--address', '127.0.0.1', "pod/$Pod", "${port}:9999")
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($forward.HasExited) { throw 'Private port-forward exited before the read.' }
        try {
            $probe = [Net.Sockets.TcpClient]::new()
            $probe.Connect('127.0.0.1', $port)
            $probe.Dispose()
            $ready = $true
            break
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $ready) { throw 'Private port-forward did not become ready.' }

    $encodedUser = kubectl -n $Namespace get secret wai-pf13-administrator -o 'jsonpath={.data.username}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the administrator username.' }
    $encodedPassword = kubectl -n $Namespace get secret wai-pf13-administrator -o 'jsonpath={.data.password}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the administrator password.' }

    $env:PF_ADMIN_URL = "https://localhost:$port/pf-admin-api/v1"
    $env:PF_ADMIN_USERNAME = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedUser)).Trim()
    $env:PF_ADMIN_PASSWORD = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedPassword)).Trim()
    $env:PF_ADMIN_INSECURE = 'false'
    $env:SSL_CERT_FILE = $adminCa
    python (Join-Path $repoRoot 'deploy/pingfederate/scripts/read_actor_jwks_kids.py')
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the actor token processor.' }
} finally {
    foreach ($name in @('PF_ADMIN_URL', 'PF_ADMIN_USERNAME', 'PF_ADMIN_PASSWORD', 'PF_ADMIN_INSECURE', 'SSL_CERT_FILE')) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    if ($null -ne $forward -and -not $forward.HasExited) { Stop-Process -Id $forward.Id -Force }
}
