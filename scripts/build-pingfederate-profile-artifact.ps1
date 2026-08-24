param(
    [string]$ImageReference = 'wai-pingfederate-profile:validation',
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dockerfile = Join-Path $root 'deploy/pingfederate/profile-artifact/Dockerfile'
$plugin = Join-Path $root 'deploy/pingfederate/profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar'
$hook = Join-Path $root 'deploy/pingfederate/profile/hooks/02-get-remote-server-profile.sh.post'

if ($ImageReference -notmatch '^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or $ImageReference.Contains('..') -or $ImageReference.EndsWith(':latest')) {
    throw 'Profile artifact image reference must be an explicit non-latest registry tag.'
}
if (-not (Test-Path -LiteralPath $dockerfile -PathType Leaf)) { throw 'Reviewed profile artifact Dockerfile is missing.' }

& (Join-Path $PSScriptRoot 'build-pingfederate-profile.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Reviewed PingFederate plugin build failed.' }

foreach ($inputFile in @($plugin, $hook)) {
    if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) { throw 'Required profile artifact input is missing.' }
    $info = Get-Item -LiteralPath $inputFile -Force
    if ($info.LinkType -or $info.Length -le 0 -or $info.Length -gt 16MB) { throw 'Profile artifact input must be a bounded regular non-symlink file.' }
}
if ((Get-Item -LiteralPath $plugin).Length -lt 1024) { throw 'Profile plugin artifact is unexpectedly small.' }

$revision = (& git -C $root rev-parse --verify HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'A verified Git source revision is required.' }
if ($Push -and (& git -C $root status --porcelain)) { throw 'Refusing to publish the profile artifact from a dirty Git tree.' }

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $temporaryBase ('wai-pf-profile-' + [IO.Path]::GetRandomFileName())))
if (-not $temporaryRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($temporaryRoot) -notmatch '^wai-pf-profile-[A-Za-z0-9.]+$') {
    throw 'Could not establish a bounded profile artifact temporary directory.'
}
$context = Join-Path $temporaryRoot 'context'
$outputTar = Join-Path $temporaryRoot 'artifact.tar'
try {
    $deployDirectory = Join-Path $context 'profile/instance/server/default/deploy'
    $hookDirectory = Join-Path $context 'profile/hooks'
    [IO.Directory]::CreateDirectory($deployDirectory) | Out-Null
    [IO.Directory]::CreateDirectory($hookDirectory) | Out-Null
    Copy-Item -LiteralPath $dockerfile -Destination (Join-Path $context 'Dockerfile')
    Copy-Item -LiteralPath $plugin -Destination (Join-Path $deployDirectory 'wai-pingfederate-spiffe-plugins.jar')
    Copy-Item -LiteralPath $hook -Destination (Join-Path $hookDirectory '02-get-remote-server-profile.sh.post')

    $contextFiles = @(Get-ChildItem -LiteralPath $context -Recurse -File -Force)
    $expectedContext = @(
        'Dockerfile',
        'profile/hooks/02-get-remote-server-profile.sh.post',
        'profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar'
    )
    $actualContext = @($contextFiles | ForEach-Object { [IO.Path]::GetRelativePath($context, $_.FullName).Replace('\', '/') } | Sort-Object)
    if (Compare-Object $expectedContext $actualContext) { throw 'Profile artifact staging context contains an unexpected or missing file.' }
    if ($contextFiles | Where-Object { $_.LinkType }) { throw 'Profile artifact staging context contains a symbolic link.' }

    foreach ($file in $contextFiles) {
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        try {
            $text = [Text.Encoding]::ASCII.GetString($bytes)
            if ($text -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----' -or
                $text -match '(?im)^\s*(?:PING_IDENTITY_DEVOPS_KEY|PING_IDENTITY_PASSWORD|PF_ADMIN_PASSWORD)\s*=') {
                throw 'Profile artifact staging context contains signing material or a credential value.'
            }
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }

    if ($Push) {
        & docker buildx build --platform linux/amd64,linux/arm64 --build-arg "SOURCE_REVISION=$revision" --tag $ImageReference --push $context
        if ($LASTEXITCODE -ne 0) { throw 'Profile artifact publication failed.' }
        Write-Output "PASS: published secret-free PingFederate profile artifact from revision $revision."
    } else {
        & docker buildx build --platform linux/amd64 --build-arg "SOURCE_REVISION=$revision" --output "type=tar,dest=$outputTar" $context
        if ($LASTEXITCODE -ne 0) { throw 'Profile artifact validation build failed.' }
        $listed = @(& tar -tf $outputTar | ForEach-Object { $_.TrimStart('./').TrimEnd('/') } | Where-Object { $_ } | Sort-Object -Unique)
        $expectedOutput = @(
            'profile', 'profile/hooks', 'profile/hooks/02-get-remote-server-profile.sh.post',
            'profile/instance', 'profile/instance/server', 'profile/instance/server/default',
            'profile/instance/server/default/deploy',
            'profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar'
        )
        if (Compare-Object $expectedOutput $listed) { throw 'Built profile artifact contains an unexpected or missing path.' }
        Write-Output "PASS: built and inventoried secret-free PingFederate profile artifact from revision $revision."
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporary = [IO.Path]::GetFullPath($temporaryRoot)
        if ($resolvedTemporary -ne $temporaryRoot -or -not $resolvedTemporary.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean an unexpected profile artifact path.'
        }
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
