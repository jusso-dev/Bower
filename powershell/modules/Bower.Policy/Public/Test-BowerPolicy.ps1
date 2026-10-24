function Test-BowerPolicy {
    <#
    .SYNOPSIS
    Validates a directory of Bower telemetry policies with the bower CLI.

    .DESCRIPTION
    Runs `bower validate --policy-directory DIR`, which loads every *.yaml policy exactly
    as the collector does (strict schema, supported action, score range) and reports each
    policy's id, version and stable hash. Nothing is sent anywhere.

    A policy the loader refuses is a validation result (Valid is $false and Error holds
    the bounded loader message), not a command failure. A missing bower executable or
    directory is an error.

    .PARAMETER PolicyDirectory
    Directory of policy YAML files. Defaults to policies/default under the current directory.

    .PARAMETER BowerPath
    Path to the bower executable. Defaults to bower on PATH.

    .EXAMPLE
    Test-BowerPolicy -PolicyDirectory ./policies/default

    Validates the default policies and lists their hashes.

    .EXAMPLE
    (Test-BowerPolicy -PolicyDirectory ./policies/custom).Valid | Should -BeTrue

    Fails a Pester test when any custom policy does not load.

    .OUTPUTS
    Bower.PolicyValidation
    #>
    [CmdletBinding()]
    [OutputType('Bower.PolicyValidation')]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        [string] $PolicyDirectory = (Join-Path (Get-Location).ProviderPath 'policies/default'),

        [ValidateNotNullOrEmpty()]
        [string] $BowerPath
    )

    process {
        try {
            $directory = Resolve-BowerPolicyFile -Path $PolicyDirectory -Name 'Policy directory' -Directory
            $bower = Resolve-BowerCliPath -Name 'bower' -Path $BowerPath
            $run = Invoke-BowerCli -FilePath $bower -ArgumentList @('validate', '--policy-directory', $directory)
            $document = $null
            if ($run.ExitCode -eq 0) {
                try {
                    $document = $run.StdOut | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    $document = $null
                }
                if ($document -isnot [System.Management.Automation.PSCustomObject]) {
                    throw [System.InvalidOperationException]::new(
                        "bower validate did not return a JSON document: $(Get-BowerCliErrorText -Text $run.StdErr)")
                }
            }

            $result = [pscustomobject]@{
                Valid           = $run.ExitCode -eq 0 -and $document.valid -eq $true
                PolicyCount     = if ($document) { [int]$document.policyCount } else { 0 }
                Policies        = if ($document) {
                    @($document.policies | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Version = $_.Version; Hash = $_.Hash } })
                }
                else {
                    @()
                }
                Error           = if ($run.ExitCode -eq 0) { $null } else { Get-BowerCliErrorText -Text $run.StdErr }
                PolicyDirectory = $directory
            }
            $result.PSObject.TypeNames.Insert(0, 'Bower.PolicyValidation')
            $result
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
