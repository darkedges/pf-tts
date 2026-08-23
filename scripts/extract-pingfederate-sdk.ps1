param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destination = Join-Path $root 'deploy/pingfederate/sdk/runtime-lib'
$image = 'pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0'
$containerName = "wai-pf-sdk-extract-$PID"
$required = @('jose4j.jar', 'slf4j-api.jar', 'pingfederate-sdk.jar', 'pf-protocolengine.jar')

if ((& docker ps -a --filter "name=^/$containerName$" --format '{{.Names}}') -eq $containerName) {
    throw "Refusing to reuse existing extraction container $containerName."
}

[IO.Directory]::CreateDirectory($destination) | Out-Null
try {
    & docker create --name $containerName $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create pinned PingFederate SDK extraction container.' }
    foreach ($name in $required) {
        $target = Join-Path $destination $name
        & docker cp "${containerName}:/opt/server/server/default/lib/$name" $target
        if ($LASTEXITCODE -ne 0) { throw "Could not extract required PingFederate SDK dependency: $name" }
        $item = Get-Item -LiteralPath $target
        if ($item.Length -lt 1024) { throw "Extracted PingFederate SDK dependency is unexpectedly small: $name" }
        $stream = [IO.File]::OpenRead($target)
        try {
            if ($stream.ReadByte() -ne 0x50 -or $stream.ReadByte() -ne 0x4b) { throw "Extracted dependency is not a JAR archive: $name" }
        } finally {
            $stream.Dispose()
        }
    }
} finally {
    & docker rm -f $containerName 2>$null | Out-Null
}

Write-Output 'Extracted four reviewed build-time dependencies from the pinned PingFederate image.'
