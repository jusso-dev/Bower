function Resolve-BowerPolicyFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name,

        [switch] $Directory
    )

    $type = if ($Directory) { 'Container' } else { 'Leaf' }
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.ProviderPath -PathType $type)) {
        throw [System.IO.FileNotFoundException]::new("$Name '$Path' was not found.")
    }
    $resolved.ProviderPath
}

function Invoke-BowerPolicyCli {
    <#
    Runs bower with an argument array and parses its JSON document. Exit codes listed in
    -AcceptExitCode are results, not failures (bower policy test exits 3 on an --expect
    mismatch and still prints every decision).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList,

        [string] $BowerPath,

        [int[]] $AcceptExitCode = @(0)
    )

    $bower = Resolve-BowerCliPath -Name 'bower' -Path $BowerPath
    $run = Invoke-BowerCli -FilePath $bower -ArgumentList $ArgumentList
    $command = 'bower ' + (($ArgumentList | Select-Object -First 2) -join ' ')
    if ($AcceptExitCode -notcontains $run.ExitCode) {
        throw [System.InvalidOperationException]::new(
            "$command failed (exit code $($run.ExitCode)): $(Get-BowerCliErrorText -Text $run.StdErr)")
    }
    try {
        $document = $run.StdOut | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $document = $null
    }
    if ($document -isnot [System.Management.Automation.PSCustomObject]) {
        throw [System.InvalidOperationException]::new(
            "$command did not return a JSON document (exit code $($run.ExitCode)): $(Get-BowerCliErrorText -Text $run.StdErr)")
    }
    [pscustomobject]@{ ExitCode = $run.ExitCode; Document = $document }
}

function Get-BowerPolicySourceArgument {
    <# Bundle options shared by bower validate and bower policy test. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [string] $PolicyDirectory,

        [string[]] $PackPath,

        [string[]] $TrustedKeyPath,

        [string] $PrivacyProfilePath,

        [string] $HmacKeyFile
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    if ($PolicyDirectory) {
        $arguments.AddRange([string[]]@('--policy-directory', (Resolve-BowerPolicyFile -Path $PolicyDirectory -Name 'Policy directory' -Directory)))
    }
    foreach ($pack in $PackPath) {
        $arguments.AddRange([string[]]@('--pack', (Resolve-BowerPolicyFile -Path $pack -Name 'Pack')))
    }
    foreach ($key in $TrustedKeyPath) {
        $arguments.AddRange([string[]]@('--trusted-key', (Resolve-BowerPolicyFile -Path $key -Name 'Trusted key')))
    }
    if ($PrivacyProfilePath) {
        $arguments.AddRange([string[]]@('--privacy-profile', (Resolve-BowerPolicyFile -Path $PrivacyProfilePath -Name 'Privacy profile')))
    }
    if ($HmacKeyFile) {
        $arguments.AddRange([string[]]@('--hmac-key-file', (Resolve-BowerPolicyFile -Path $HmacKeyFile -Name 'HMAC key file')))
    }
    , $arguments.ToArray()
}
