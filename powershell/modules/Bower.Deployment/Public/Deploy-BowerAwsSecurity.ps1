function Deploy-BowerAwsSecurity {
    <#
    .SYNOPSIS
    Plans (default) or applies the existing Bower AWS security or global forwarder stacks.

    .DESCRIPTION
    Wraps `aws cloudformation deploy` for deploy/aws/bower-aws-security.yaml (Security:
    SQS queue, EventBridge rules that start DISABLED, optional app-log Firehose) or
    deploy/aws/bower-aws-global-forwarder.yaml (GlobalForwarder: forwards a region's
    events to the home event bus). By default --no-execute-changeset creates a change set
    and executes nothing. -Apply executes after ShouldProcess confirmation (ConfirmImpact
    High). -WhatIf runs nothing.

    .PARAMETER Template
    Security or GlobalForwarder.

    .PARAMETER ParameterOverride
    Template parameters, for example @{ RuleState = 'DISABLED' } or
    @{ HomeEventBusArn = 'arn:aws:events:ap-southeast-2:123456789012:event-bus/default' }.

    .PARAMETER StackName
    Stack name. Defaults to bower-security or bower-global-forwarder.

    .PARAMETER Region
    AWS region. Default ap-southeast-2 (Sydney).

    .PARAMETER ProfileName
    AWS CLI profile.

    .PARAMETER TemplatePath
    Template path override.

    .PARAMETER AwsPath
    Path to the aws executable. Defaults to aws on PATH.

    .PARAMETER Apply
    Execute the deployment instead of only creating a change set. Requires confirmation.

    .EXAMPLE
    Deploy-BowerAwsSecurity -Template Security -ParameterOverride @{ RuleState = 'DISABLED' }

    Creates a change set for the security stack with rules disabled.

    .EXAMPLE
    Deploy-BowerAwsSecurity -Template GlobalForwarder -Region us-east-1 `
        -ParameterOverride @{ HomeEventBusArn = 'arn:aws:events:ap-southeast-2:123456789012:event-bus/default' } -Apply

    Deploys the global forwarder in us-east-1 after confirmation.

    .OUTPUTS
    Bower.DeploymentPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Security', 'GlobalForwarder')]
        [string] $Template,

        [System.Collections.IDictionary] $ParameterOverride = @{},

        [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,127}$')]
        [string] $StackName,

        [ValidatePattern('^[a-z]{2}(-[a-z]+)+-\d+$')]
        [string] $Region = 'ap-southeast-2',

        [ValidateNotNullOrEmpty()]
        [string] $ProfileName,

        [string] $TemplatePath,

        [string] $AwsPath,

        [switch] $Apply
    )

    try {
        $default = if ($Template -eq 'Security') { 'deploy/aws/bower-aws-security.yaml' } else { 'deploy/aws/bower-aws-global-forwarder.yaml' }
        if (-not $StackName) {
            $StackName = if ($Template -eq 'Security') { 'bower-security' } else { 'bower-global-forwarder' }
        }
        foreach ($key in $ParameterOverride.Keys) {
            if ([string]$key -notmatch '^[A-Za-z0-9]{1,255}$') {
                throw [System.ArgumentException]::new("Parameter name '$key' is not a valid CloudFormation parameter name.")
            }
        }

        $templateFile = Resolve-BowerTemplatePath -Path $TemplatePath -Default $default
        $parameters = [ordered]@{}
        foreach ($key in @($ParameterOverride.Keys | Sort-Object)) {
            $parameters[[string]$key] = $ParameterOverride[$key]
        }

        $target = "stack '$StackName' in $Region"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, "Deploy Bower AWS $Template stack (aws cloudformation deploy)")) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Create change set (aws cloudformation deploy --no-execute-changeset)')
            'Preview'
        }
        else {
            'Plan'
        }

        Invoke-BowerCloudFormationDeployment -Name "aws-$($Template.ToLowerInvariant())" -TemplatePath $templateFile -StackName $StackName `
            -Region $Region -ProfileName $ProfileName -Parameters $parameters -Capability @('CAPABILITY_IAM') -Mode $mode -AwsPath $AwsPath -RemainingChecks @(
            'Review the change set before -Apply.',
            'Enable rules (RuleState=ENABLED) only after the collector, packs and agent are validated.'
        )
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
