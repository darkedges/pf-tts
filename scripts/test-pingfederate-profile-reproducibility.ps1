param()

$ErrorActionPreference = 'Stop'
$builder = Join-Path $PSScriptRoot 'build-pingfederate-profile.ps1'
$artifact = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../deploy/pingfederate/profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar'))

& $builder
$first = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
& $builder
$second = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
if ($first -ne $second) {
    throw 'PingFederate profile plugin build is not reproducible.'
}
Write-Output "Verified reproducible PingFederate profile plugin: sha256=$second"
