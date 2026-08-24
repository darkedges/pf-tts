param(
    [string]$ImageReference = 'wai-pingfederate-runtime:validation',
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dockerfile = Join-Path $root 'deploy/pingfederate/runtime-image/Dockerfile'
$plugin = Join-Path $root 'deploy/pingfederate/profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar'
if ($ImageReference -notmatch '^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or $ImageReference.Contains('..') -or $ImageReference.EndsWith(':latest')) {
    throw 'PingFederate runtime image reference must use an explicit non-latest tag.'
}
& (Join-Path $PSScriptRoot 'build-pingfederate-profile.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Reviewed PingFederate plugin build failed.' }
foreach ($input in @($dockerfile, $plugin)) {
    $item = Get-Item -LiteralPath $input -Force -ErrorAction Stop
    if ($item.LinkType -or $item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 16MB) { throw 'Runtime image input must be a bounded regular non-symlink file.' }
}
$revision = (& git -C $root rev-parse --verify HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'A verified Git source revision is required.' }
if ($Push -and (& git -C $root status --porcelain)) { throw 'Refusing to publish the PingFederate runtime image from a dirty Git tree.' }

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $temporaryBase ('wai-pf-runtime-' + [IO.Path]::GetRandomFileName())))
if (-not $temporaryRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($temporaryRoot) -notmatch '^wai-pf-runtime-[A-Za-z0-9.]+$') { throw 'Could not establish a bounded runtime-image context.' }
try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    Copy-Item -LiteralPath $dockerfile -Destination (Join-Path $temporaryRoot 'Dockerfile')
    Copy-Item -LiteralPath $plugin -Destination (Join-Path $temporaryRoot 'wai-pingfederate-spiffe-plugins.jar')
    $files = @(Get-ChildItem -LiteralPath $temporaryRoot -File -Force)
    $actual = @($files.Name | Sort-Object)
    $expected = @('Dockerfile', 'wai-pingfederate-spiffe-plugins.jar')
    if (Compare-Object $expected $actual) { throw 'Runtime-image context contains an unexpected or missing file.' }
    if ($files | Where-Object { $_.LinkType }) { throw 'Runtime-image context contains a symbolic link.' }
    foreach ($file in $files) {
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        try {
            $text = [Text.Encoding]::ASCII.GetString($bytes)
            $credentialScan = $text -replace '(?m)^\s*PING_IDENTITY_PASSWORD=""\s*\\\s*$', ''
            if ($credentialScan -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----' -or $credentialScan -match '(?im)^\s*(?:PING_IDENTITY_DEVOPS_KEY|PING_IDENTITY_PASSWORD|PF_ADMIN_PASSWORD)\s*=') { throw 'Runtime-image context contains credential or signing material.' }
        } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    if ($Push) {
        & docker buildx build --platform linux/amd64,linux/arm64 --build-arg "SOURCE_REVISION=$revision" --tag $ImageReference --push $temporaryRoot
        if ($LASTEXITCODE -ne 0) { throw 'PingFederate runtime image publication failed.' }
        Write-Output "PASS: published baked PingFederate runtime image from revision $revision."
    } else {
        & docker buildx build --platform linux/amd64 --build-arg "SOURCE_REVISION=$revision" --tag $ImageReference --load $temporaryRoot
        if ($LASTEXITCODE -ne 0) { throw 'PingFederate runtime validation image build failed.' }
        Write-Output "PASS: built baked PingFederate runtime validation image from revision $revision."
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        if ($resolved -ne $temporaryRoot -or -not $resolved.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to clean an unexpected runtime-image path.' }
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
