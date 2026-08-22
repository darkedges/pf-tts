param(
    [string]$EnvFile,

    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ScriptPath,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArguments
)

$ErrorActionPreference = 'Stop'

if ($EnvFile) {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        throw "Environment file not found: $EnvFile"
    }
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            throw "Invalid environment assignment in $EnvFile"
        }
        $name = $Matches[1]
        $value = $Matches[2].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

function Find-PythonExecutable {
    foreach ($name in @('python3', 'python')) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return @($command.Source)
        }
    }

    $launcher = Get-Command py -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $launcher) {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $launcher.Source -3 --version 2> $null
        $launcherExitCode = $LASTEXITCODE
        $ErrorActionPreference = $savedPreference
        if ($launcherExitCode -eq 0) {
            return @($launcher.Source, '-3')
        }
    }

    $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundled -PathType Leaf) {
        return @($bundled)
    }

    throw 'Python 3 was not found. Install Python 3 or override PYTHON_RUN when invoking make.'
}

$python = @(Find-PythonExecutable)
$executable = $python[0]
$launcherArguments = @($python | Select-Object -Skip 1)

& $executable @launcherArguments $ScriptPath @ScriptArguments
exit $LASTEXITCODE
