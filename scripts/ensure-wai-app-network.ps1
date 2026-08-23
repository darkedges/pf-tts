param()

$ErrorActionPreference = 'Stop'
$networkName = 'docker_wai-app'
$driver = & docker network inspect $networkName --format '{{.Driver}}' 2>$null
if ($LASTEXITCODE -ne 0) {
    & docker network create --driver bridge $networkName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create local application network $networkName." }
    $driver = 'bridge'
}
if (($driver | Out-String).Trim() -ne 'bridge') {
    throw "Existing network $networkName must use the bridge driver."
}
Write-Output "Validated local application network: $networkName"
