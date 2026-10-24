# Shared by Bower.Privacy and Bower.Deployment. Keep both copies byte-identical
# (powershell/tests/Repository.Tests.ps1 enforces it). Every external CLI call goes
# through Invoke-BowerCli so tests can mock it; tests never run real cloud CLIs.

function Resolve-BowerCliPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [string] $Path
    )

    if ($Path) {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
        if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.ProviderPath -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("'$Path' was not found.")
        }
        return $resolved.ProviderPath
    }

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        throw [System.Management.Automation.CommandNotFoundException]::new("'$Name' was not found on PATH. Install it or pass its path.")
    }
    $command.Source
}

function Invoke-BowerCli {
    <#
    Runs an external command with an argument array (no shell, no string evaluation) and
    returns { ExitCode; StdOut; StdErr }. Arguments must never contain secrets.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [string[]] $ArgumentList = @()
    )

    $PSNativeCommandUseErrorActionPreference = $false
    Write-Verbose ('Running {0} {1}' -f [System.IO.Path]::GetFileName($FilePath), ($ArgumentList -join ' '))
    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE

    $stdout = [System.Collections.Generic.List[string]]::new()
    $stderr = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $output) {
        if ($line -is [System.Management.Automation.ErrorRecord]) {
            $stderr.Add($line.ToString())
        }
        else {
            $stdout.Add([string]$line)
        }
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        StdOut   = $stdout -join [System.Environment]::NewLine
        StdErr   = $stderr -join [System.Environment]::NewLine
    }
}

function Get-BowerCliErrorText {
    <# First lines of stderr, bounded, for error messages. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 'no error output'
    }
    $trimmed = $Text.Trim()
    if ($trimmed.Length -gt 1000) {
        $trimmed = $trimmed.Substring(0, 1000) + '...'
    }
    $trimmed
}
