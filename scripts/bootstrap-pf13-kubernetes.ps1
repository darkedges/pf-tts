param(
    [string]$Namespace = 'wai-pingfederate',
    [string]$Release = 'wai-pingfederate',
    [string]$Pod = 'wai-pingfederate-0',
    [string]$Chart = 'deploy/helm/wai-pingfederate',
    [int]$TimeoutMinutes = 15
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Namespace -ne 'wai-pingfederate' -or $Release -ne 'wai-pingfederate' -or $Pod -ne 'wai-pingfederate-0') {
    throw 'Bootstrap is restricted to the exact isolated PingFederate release.'
}
if ($TimeoutMinutes -lt 5 -or $TimeoutMinutes -gt 30) { throw 'TimeoutMinutes must be between 5 and 30.' }
foreach ($command in @('git', 'helm', 'kubectl', 'python')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command is required." }
}
if (git status --porcelain) { throw 'Refusing Kubernetes bootstrap from a dirty Git tree.' }

$chartPath = [IO.Path]::GetFullPath((Join-Path (Get-Location) $Chart))
if (-not (Test-Path -LiteralPath (Join-Path $chartPath 'Chart.yaml') -PathType Leaf)) { throw 'Chart path is invalid.' }
$claim = "out-pf13-two-phase-$Release-0"
kubectl -n $Namespace get pvc $claim *> $null
if ($LASTEXITCODE -eq 0) { throw "Refusing to bootstrap over existing PVC $claim." }
if ($LASTEXITCODE -ne 1) { throw 'Could not establish that the bootstrap PVC is absent.' }

$timeout = "${TimeoutMinutes}m"
kubectl -n $Namespace delete statefulset $Release --cascade=orphan
if ($LASTEXITCODE -ne 0) { throw 'Could not remove the isolated StatefulSet controller.' }
kubectl -n $Namespace delete pod $Pod --ignore-not-found=true --wait=true --timeout=120s
if ($LASTEXITCODE -ne 0) { throw 'Could not remove the isolated pod.' }

helm upgrade $Release $chartPath --namespace $Namespace --set adminApi.bootstrapNewInstance=true --wait --timeout $timeout
if ($LASTEXITCODE -ne 0) { throw 'Unauthenticated bootstrap phase failed.' }

kubectl -n $Namespace exec $Pod -- sh -ceu "test \"`$(grep -c '<user-name>administrator</user-name>' /opt/out/instance/server/default/data/pingfederate-admin-user.xml)\" -eq 1"
if ($LASTEXITCODE -ne 0) { throw 'Vendor bootstrap did not create exactly one expected administrator account.' }

helm upgrade $Release $chartPath --namespace $Namespace --set adminApi.bootstrapNewInstance=false --wait --timeout $timeout
if ($LASTEXITCODE -ne 0) { throw 'Native-authentication transition failed.' }

$mode = kubectl -n $Namespace get statefulset $Release -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="PF_ADMIN_API_AUTHENTICATION")].value}'
if ($LASTEXITCODE -ne 0 -or $mode -ne 'native') { throw 'Native Admin API authentication was not applied exactly.' }

& (Join-Path $PSScriptRoot 'export-pf13-kubernetes-admin-ca.ps1') -Namespace $Namespace -Pod $Pod
if ($LASTEXITCODE -ne 0) { throw 'Admin TLS leaf attestation failed.' }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$forward = $null
try {
    $forward = Start-Process kubectl -WindowStyle Hidden -PassThru -ArgumentList @('-n', $Namespace, 'port-forward', '--address', '127.0.0.1', "pod/$Pod", "${port}:9999")
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($forward.HasExited) { throw 'Private port-forward exited before attestation.' }
        try {
            $client = [Net.Sockets.TcpClient]::new()
            $client.Connect('127.0.0.1', $port)
            $client.Dispose()
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) { throw 'Private port-forward did not become ready.' }

    $encodedUser = kubectl -n $Namespace get secret wai-pf13-administrator -o jsonpath='{.data.username}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the exact administrator username field.' }
    $encodedPassword = kubectl -n $Namespace get secret wai-pf13-administrator -o jsonpath='{.data.password}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the exact administrator password field.' }
    $username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedUser))
    $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedPassword))
    if ($username -ne 'administrator' -or [string]::IsNullOrWhiteSpace($password)) { throw 'Administrator secret does not match the reviewed account contract.' }

    $env:PF_ADMIN_USERNAME = $username
    $env:PF_ADMIN_PASSWORD = $password
    $env:PF_ADMIN_URL = "https://localhost:$port/pf-admin-api/v1"
    $env:SSL_CERT_FILE = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../deploy/pingfederate/generated/pf13-kubernetes-admin-ca.pem'))
    $env:PF_ADMIN_INSECURE = 'false'
    python (Join-Path $PSScriptRoot '../deploy/pingfederate/scripts/discover_pf_plugins.py')
    if ($LASTEXITCODE -ne 0) { throw 'Authenticated version and descriptor attestation failed.' }
} finally {
    Remove-Item Env:PF_ADMIN_PASSWORD, Env:PF_ADMIN_USERNAME, Env:PF_ADMIN_URL, Env:SSL_CERT_FILE, Env:PF_ADMIN_INSECURE -ErrorAction SilentlyContinue
    if ($null -ne $forward -and -not $forward.HasExited) { Stop-Process -Id $forward.Id -Force }
}

Write-Output 'PASS: completed isolated two-phase PingFederate bootstrap and authenticated descriptor attestation.'
