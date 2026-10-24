function Deploy-BowerGcpSecurity {
    <#
    .SYNOPSIS
    Plans (default) or applies the Bower Google Cloud Terraform in deploy/gcp.

    .DESCRIPTION
    Plan mode runs `terraform init -input=false` and
    `terraform plan -input=false -var-file=<VarFile> -out=<PlanFile>` and refuses to
    overwrite an existing plan file. Apply mode runs
    `terraform apply -input=false <PlanFile>` for a plan you already reviewed, after
    ShouldProcess confirmation (ConfirmImpact High). -WhatIf runs nothing.

    .PARAMETER VarFile
    terraform.tfvars file (see deploy/gcp/terraform.tfvars.example). Required for plan.

    .PARAMETER PlanFile
    Plan output (plan mode) or reviewed plan to apply (apply mode).

    .PARAMETER WorkingDirectory
    Terraform directory. Defaults to deploy/gcp in this repository.

    .PARAMETER TerraformPath
    Path to the terraform executable. Defaults to terraform on PATH.

    .PARAMETER Apply
    Apply the reviewed -PlanFile. Requires confirmation.

    .EXAMPLE
    Deploy-BowerGcpSecurity -VarFile ./prod.tfvars -PlanFile ./bower-gcp.tfplan

    Writes a plan for review. Nothing is changed.

    .EXAMPLE
    Deploy-BowerGcpSecurity -PlanFile ./bower-gcp.tfplan -Apply

    Applies the reviewed plan after confirmation.

    .OUTPUTS
    Bower.DeploymentPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $VarFile,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $PlanFile,

        [string] $WorkingDirectory,

        [string] $TerraformPath,

        [switch] $Apply
    )

    try {
        $directory = Resolve-BowerTemplatePath -Path $WorkingDirectory -Default 'deploy/gcp'
        $mainFile = Join-Path $directory 'main.tf'
        if (-not (Test-Path -LiteralPath $mainFile -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("'$directory' does not contain main.tf.")
        }
        $planPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PlanFile)
        $parameters = [ordered]@{ planFile = $planPath }

        if ($Apply) {
            if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
                throw [System.IO.FileNotFoundException]::new("Reviewed plan '$PlanFile' was not found. Run Deploy-BowerGcpSecurity without -Apply first.")
            }
            $commands = @(, @("-chdir=$directory", 'apply', '-input=false', $planPath))
        }
        else {
            if (-not $VarFile) {
                throw [System.ArgumentException]::new('-VarFile is required to create a plan.')
            }
            if (Test-Path -LiteralPath $planPath) {
                throw [System.IO.IOException]::new("Plan file '$PlanFile' already exists; select a new path so earlier review evidence is not overwritten.")
            }
            $varPath = (Resolve-Path -LiteralPath $VarFile -ErrorAction Stop).ProviderPath
            $parameters.varFile = $varPath
            $commands = @(
                @("-chdir=$directory", 'init', '-input=false'),
                @("-chdir=$directory", 'plan', '-input=false', "-var-file=$varPath", "-out=$planPath")
            )
        }

        $target = "Google Cloud Terraform in '$directory'"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, "Apply reviewed plan '$PlanFile' (terraform apply)")) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Plan (terraform init and plan)')
            'Preview'
        }
        else {
            'Plan'
        }

        $output = @()
        if ($mode -ne 'Preview') {
            $terraform = Resolve-BowerCliPath -Name 'terraform' -Path $TerraformPath
            $output = foreach ($arguments in $commands) {
                Invoke-BowerCliChecked -FilePath $terraform -ArgumentList $arguments
            }
        }

        New-BowerDeploymentPlan -Name 'gcp-security' -Mode $mode -Tool 'terraform' -Template $mainFile -Parameters $parameters `
            -Commands @($commands | ForEach-Object { "terraform $($_ -join ' ')" }) -Executed ($mode -ne 'Preview') -Result ($output -join [System.Environment]::NewLine) -RemainingChecks @(
            'Review the plan (terraform show <PlanFile>) before -Apply.',
            'Keep persistence regions Australian and subscriber access consume-only.'
        )
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
