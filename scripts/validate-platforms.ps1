$ErrorActionPreference = 'Stop'

$originalGOOS = $env:GOOS
$originalGOARCH = $env:GOARCH
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    & go build ./cmd/...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    & go build ./cmd/...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:GOOS = $originalGOOS
    $env:GOARCH = $originalGOARCH
}

Write-Output 'Windows and Linux amd64 command builds passed.'
