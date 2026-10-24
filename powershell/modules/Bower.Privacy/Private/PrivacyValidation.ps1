function Resolve-BowerExistingFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.ProviderPath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("$Name '$Path' was not found.")
    }
    $resolved.ProviderPath
}

function Invoke-BowerLocalPrivacyValidation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [string] $HmacKeyFile,

        [string] $SamplePath,

        [string] $BowerPath
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@('privacy', 'validate', (Resolve-BowerExistingFile -Path $Path -Name 'Privacy profile')))
    if ($HmacKeyFile) {
        $arguments.AddRange([string[]]@('--hmac-key-file', (Resolve-BowerExistingFile -Path $HmacKeyFile -Name 'HMAC key file')))
    }
    if ($SamplePath) {
        $arguments.AddRange([string[]]@('--sample', (Resolve-BowerExistingFile -Path $SamplePath -Name 'Sample')))
    }

    $bower = Resolve-BowerCliPath -Name 'bower' -Path $BowerPath
    $run = Invoke-BowerCli -FilePath $bower -ArgumentList $arguments.ToArray()

    $summary = $null
    if (-not [string]::IsNullOrWhiteSpace($run.StdOut)) {
        try {
            $summary = $run.StdOut | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $summary = $null
        }
    }
    if ($summary -isnot [System.Management.Automation.PSCustomObject]) {
        throw [System.InvalidOperationException]::new(
            "bower privacy validate did not return a JSON summary (exit code $($run.ExitCode)): $(Get-BowerCliErrorText -Text $run.StdErr)")
    }

    $valid = @($summary.PSObject.Properties.Name) -contains 'valid' -and $summary.valid -eq $true
    if ($run.ExitCode -ne 0 -and $valid) {
        Write-Warning "bower privacy validate reported valid but exited with code $($run.ExitCode)."
    }
    $summary
}

function Invoke-BowerRemotePrivacyValidation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Path,

        [string] $Content
    )

    $request = Get-Command -Name Invoke-BowerManagementRequest -ErrorAction SilentlyContinue
    if (-not $request) {
        throw [System.InvalidOperationException]::new(
            'Test-BowerPrivacyProfile -Remote needs Bower.Management: Import-Module Bower.Management, then run Connect-BowerManagement.')
    }

    if ($Path -and $Content) {
        throw [System.ArgumentException]::new('Use -Path or -Content, not both.')
    }
    $text = if ($Path) {
        [System.IO.File]::ReadAllText((Resolve-BowerExistingFile -Path $Path -Name 'Privacy profile'), [System.Text.Encoding]::UTF8)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Content)) {
        $Content
    }
    else {
        throw [System.ArgumentException]::new('Privacy profile content is required (-Path or -Content).')
    }

    & $request -Method POST -Path '/privacy-profiles/validate' -Body @{ content = $text } -ErrorAction Stop
}
