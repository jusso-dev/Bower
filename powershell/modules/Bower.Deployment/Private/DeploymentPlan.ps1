# Plan-first deployment helpers. Every cloud CLI call goes through Invoke-BowerCli.
# Default mode is a plan (what-if / change set without execution / terraform plan);
# mutation needs -Apply and passes ShouldProcess (ConfirmImpact High).

# powershell/modules/Bower.Deployment -> repository root.
$script:BowerRepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))

function Resolve-BowerTemplatePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Default
    )

    $candidate = if ($Path) { $Path } else { Join-Path $script:BowerRepositoryRoot $Default }
    $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.ProviderPath)) {
        $hint = if ($Path) { '' } else { ' Pass -TemplatePath (or -WorkingDirectory) when the module is used outside the Bower repository.' }
        throw [System.IO.FileNotFoundException]::new("Deployment asset '$candidate' was not found.$hint")
    }
    $resolved.ProviderPath
}

function Get-BowerSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string] $Text
    )

    $bytes = if ($Path) { [System.IO.File]::ReadAllBytes($Path) } else { [System.Text.Encoding]::UTF8.GetBytes($Text) }
    [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function ConvertTo-BowerCanonicalJson {
    <# Sorted-key compact JSON, so plan hashes are stable for the same parameters. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Parameters
    )

    $sorted = [ordered]@{}
    foreach ($key in @($Parameters.Keys | Sort-Object -CaseSensitive)) {
        $sorted[$key] = $Parameters[$key]
    }
    $sorted | ConvertTo-Json -Depth 8 -Compress
}

function ConvertTo-BowerCliValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object] $Value,

        [ValidateSet('Json', 'Comma')]
        [string] $ArrayStyle = 'Json'
    )

    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        if ($ArrayStyle -eq 'Comma') {
            return (@($Value) -join ',')
        }
        return (ConvertTo-Json -InputObject @($Value) -Compress)
    }
    [string]$Value
}

function ConvertTo-BowerRepositoryRelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $relative = [System.IO.Path]::GetRelativePath($script:BowerRepositoryRoot, $Path)
    if ($relative.StartsWith('..', [System.StringComparison]::Ordinal)) {
        return $Path
    }
    $relative.Replace('\', '/')
}

function New-BowerDeploymentPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Preview', 'Plan', 'Apply')]
        [string] $Mode,

        [Parameter(Mandatory)]
        [string] $Tool,

        [Parameter(Mandatory)]
        [string] $Template,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Parameters,

        [Parameter(Mandatory)]
        [string[]] $Commands,

        [bool] $Executed,

        [AllowNull()]
        [object] $Result,

        [string[]] $RemainingChecks = @()
    )

    $templateHash = Get-BowerSha256 -Path $Template
    $parametersHash = Get-BowerSha256 -Text (ConvertTo-BowerCanonicalJson -Parameters $Parameters)
    [pscustomobject]@{
        PSTypeName       = 'Bower.DeploymentPlan'
        Name             = $Name
        Mode             = $Mode
        Tool             = $Tool
        Template         = ConvertTo-BowerRepositoryRelativePath -Path $Template
        TemplateSha256   = $templateHash
        Parameters       = $Parameters
        ParametersSha256 = $parametersHash
        PlanSha256       = Get-BowerSha256 -Text "${templateHash}:${parametersHash}"
        Commands         = $Commands
        Executed         = $Executed
        MutationsApplied = $Executed -and $Mode -eq 'Apply'
        Result           = $Result
        RemainingChecks  = $RemainingChecks
    }
}

function Invoke-BowerCliChecked {
    <# Runs a CLI and throws with bounded stderr on a non-zero exit code. Parses JSON stdout when possible. #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [string[]] $ArgumentList,

        [switch] $Json
    )

    $run = Invoke-BowerCli -FilePath $FilePath -ArgumentList $ArgumentList
    if ($run.ExitCode -ne 0) {
        throw [System.InvalidOperationException]::new(
            "$([System.IO.Path]::GetFileName($FilePath)) $($ArgumentList[0..1] -join ' ') failed with exit code $($run.ExitCode): $(Get-BowerCliErrorText -Text $run.StdErr)")
    }
    if ($Json -and -not [string]::IsNullOrWhiteSpace($run.StdOut)) {
        try {
            return $run.StdOut | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Verbose 'CLI output was not JSON; returning text.'
        }
    }
    $run.StdOut
}

function Invoke-BowerAzDeployment {
    <#
    Shared Bicep flow: az deployment group what-if (plan) or create (apply). The caller
    performs ShouldProcess; this function only builds and runs the command.
    #>
    [CmdletBinding()]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $TemplatePath,

        [Parameter(Mandatory)]
        [string] $ResourceGroupName,

        [string] $SubscriptionId,

        [Parameter(Mandatory)]
        [string] $DeploymentName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Parameters,

        [Parameter(Mandatory)]
        [ValidateSet('Preview', 'Plan', 'Apply')]
        [string] $Mode,

        [string] $AzPath,

        [string[]] $RemainingChecks = @()
    )

    $operation = if ($Mode -eq 'Apply') { 'create' } else { 'what-if' }
    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@('deployment', 'group', $operation, '--resource-group', $ResourceGroupName, '--name', $DeploymentName, '--template-file', $TemplatePath))
    if ($SubscriptionId) {
        $arguments.AddRange([string[]]@('--subscription', $SubscriptionId))
    }
    if ($Parameters.Count -gt 0) {
        $arguments.Add('--parameters')
        foreach ($key in $Parameters.Keys) {
            $arguments.Add("$key=$(ConvertTo-BowerCliValue -Value $Parameters[$key])")
        }
    }
    if ($Mode -eq 'Apply') {
        $arguments.AddRange([string[]]@('--output', 'json', '--only-show-errors'))
    }
    else {
        $arguments.AddRange([string[]]@('--no-pretty-print', '--only-show-errors'))
    }

    $result = $null
    $executed = $false
    if ($Mode -ne 'Preview') {
        $az = Resolve-BowerCliPath -Name 'az' -Path $AzPath
        $result = Invoke-BowerCliChecked -FilePath $az -ArgumentList $arguments.ToArray() -Json
        $executed = $true
    }

    New-BowerDeploymentPlan -Name $Name -Mode $Mode -Tool 'az' -Template $TemplatePath -Parameters $Parameters `
        -Commands @("az $($arguments -join ' ')") -Executed $executed -Result $result -RemainingChecks $RemainingChecks
}

function Invoke-BowerCloudFormationDeployment {
    <#
    Shared CloudFormation flow: aws cloudformation deploy --no-execute-changeset (plan,
    creates a reviewable change set without executing it) or deploy (apply).
    #>
    [CmdletBinding()]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $TemplatePath,

        [Parameter(Mandatory)]
        [string] $StackName,

        [Parameter(Mandatory)]
        [string] $Region,

        [string] $ProfileName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Parameters,

        [string[]] $Capability = @(),

        [Parameter(Mandatory)]
        [ValidateSet('Preview', 'Plan', 'Apply')]
        [string] $Mode,

        [string] $AwsPath,

        [string[]] $RemainingChecks = @()
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@('cloudformation', 'deploy', '--stack-name', $StackName, '--template-file', $TemplatePath, '--region', $Region))
    if ($ProfileName) {
        $arguments.AddRange([string[]]@('--profile', $ProfileName))
    }
    if ($Parameters.Count -gt 0) {
        $arguments.Add('--parameter-overrides')
        foreach ($key in $Parameters.Keys) {
            $arguments.Add("$key=$(ConvertTo-BowerCliValue -Value $Parameters[$key] -ArrayStyle Comma)")
        }
    }
    if ($Capability.Count -gt 0) {
        $arguments.Add('--capabilities')
        $arguments.AddRange([string[]]$Capability)
    }
    if ($Mode -ne 'Apply') {
        $arguments.Add('--no-execute-changeset')
    }
    $arguments.Add('--no-fail-on-empty-changeset')

    $result = $null
    $executed = $false
    if ($Mode -ne 'Preview') {
        $aws = Resolve-BowerCliPath -Name 'aws' -Path $AwsPath
        $result = Invoke-BowerCliChecked -FilePath $aws -ArgumentList $arguments.ToArray()
        $executed = $true
    }

    New-BowerDeploymentPlan -Name $Name -Mode $Mode -Tool 'aws' -Template $TemplatePath -Parameters $Parameters `
        -Commands @("aws $($arguments -join ' ')") -Executed $executed -Result $result -RemainingChecks $RemainingChecks
}
