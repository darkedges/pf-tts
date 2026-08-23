param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $root 'deploy/pingfederate/plugins/pom.xml'
$sdk = Join-Path $root 'deploy/pingfederate/sdk/runtime-lib'
$source = Join-Path $root 'deploy/pingfederate/plugins/target/pingfederate-spiffe-plugins-0.1.0-SNAPSHOT.jar'
$destinationDirectory = Join-Path $root 'deploy/pingfederate/profile/instance/server/default/deploy'
$destination = Join-Path $destinationDirectory 'wai-pingfederate-spiffe-plugins.jar'
$bootstrapEnvironment = Join-Path $root 'deploy/pingfederate/profile/env_vars'

if (-not (Test-Path -LiteralPath $bootstrapEnvironment -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'generate-pingfederate-bootstrap-material.ps1')
}
if (-not (Test-Path -LiteralPath $bootstrapEnvironment -PathType Leaf)) {
    throw 'Missing generated PingFederate bootstrap environment material.'
}

$requiredSDK = @('jose4j.jar', 'slf4j-api.jar', 'pingfederate-sdk.jar', 'pf-protocolengine.jar')
if ($requiredSDK | Where-Object { -not (Test-Path -LiteralPath (Join-Path $sdk $_) -PathType Leaf) }) {
    & (Join-Path $PSScriptRoot 'extract-pingfederate-sdk.ps1')
}
foreach ($required in $requiredSDK) {
    if (-not (Test-Path -LiteralPath (Join-Path $sdk $required) -PathType Leaf)) {
        throw "Missing reviewed PingFederate SDK dependency: $required. Extract the matching 13.1 runtime libraries first."
    }
}

& mvn --batch-mode --no-transfer-progress -f $project clean test package
if ($LASTEXITCODE -ne 0) { throw 'PingFederate plugin build or tests failed.' }
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Expected exactly one known plugin build artifact.' }

[IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
Copy-Item -LiteralPath $source -Destination $destination -Force
$artifact = Get-Item -LiteralPath $destination
if ($artifact.Length -lt 1024) { throw 'Generated PingFederate plugin artifact is unexpectedly small.' }
$hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
Write-Output "Built reviewed PingFederate profile plugin: sha256=$hash"
