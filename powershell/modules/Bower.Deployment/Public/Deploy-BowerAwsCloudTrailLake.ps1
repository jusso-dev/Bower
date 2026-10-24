function Deploy-BowerAwsCloudTrailLake {
    <#
    .SYNOPSIS
    Plans (default) or applies the Bower CloudTrail Lake Lambda stack from deploy/aws/bower-aws-cloudtrail-lake.yaml.

    .DESCRIPTION
    Wraps `aws cloudformation deploy`. By default it passes --no-execute-changeset, which
    creates a reviewable change set and executes nothing (for a new stack, CloudFormation
    shows it in REVIEW_IN_PROGRESS). -Apply executes the deployment only after
    ShouldProcess confirmation (ConfirmImpact High). -WhatIf runs nothing.

    The stack deploys the Rust Lambda (code from -CodeS3Bucket/-CodeS3Key) for exactly one
    ingress: behind a Function URL with AuthType AWS_IAM (-IngressMode function-url, the
    default) or for direct Invoke attributed to -InvokeProducer (-IngressMode invoke).
    Deploy two stacks to offer both. For a Function URL stack, also apply
    deploy/aws/policies/bower-lambda-deny-direct-invoke-scp.json as an SCP or
    permissions-boundary Deny: resource policies cannot stop same-account principals with
    identity-policy lambda:InvokeFunction from invoking the function directly.

    .PARAMETER CodeS3Bucket
    S3 bucket holding the Lambda deployment package.

    .PARAMETER CodeS3Key
    S3 key of the Lambda deployment package.

    .PARAMETER AllowedInvokerPrincipalArns
    IAM principal ARNs allowed to invoke the function (through the URL, or directly for -IngressMode invoke).

    .PARAMETER IngressMode
    function-url (default) or invoke. One ingress per stack; there is no mixed mode.

    .PARAMETER InvokeProducer
    Producer id for direct Invoke payloads. Required with -IngressMode invoke, not allowed with function-url.

    .PARAMETER ExistingChannelArn
    ChannelArn output of another Bower CloudTrail Lake stack in the same account. The stack then
    creates no event data store or channel (use it for the second, invoke stack).

    .PARAMETER RetentionDays
    CloudTrail Lake event data store retention in days.

    .PARAMETER StackName
    Stack name. Default bower-cloudtrail-lake.

    .PARAMETER Region
    AWS region. Default ap-southeast-2 (Sydney).

    .PARAMETER ProfileName
    AWS CLI profile.

    .PARAMETER Capability
    CloudFormation capabilities to acknowledge. Default CAPABILITY_IAM (the Lambda role) and
    CAPABILITY_AUTO_EXPAND (the template uses the AWS::LanguageExtensions transform).

    .PARAMETER TemplatePath
    Template path. Defaults to deploy/aws/bower-aws-cloudtrail-lake.yaml in this repository.

    .PARAMETER AwsPath
    Path to the aws executable. Defaults to aws on PATH.

    .PARAMETER Apply
    Execute the deployment instead of only creating a change set. Requires confirmation.

    .EXAMPLE
    Deploy-BowerAwsCloudTrailLake -CodeS3Bucket bower-artifacts -CodeS3Key lambda/bower-lambda-0.1.0.zip `
        -AllowedInvokerPrincipalArns arn:aws:iam::123456789012:role/bower-producer -RetentionDays 365

    Creates a change set for review without executing it.

    .EXAMPLE
    Deploy-BowerAwsCloudTrailLake @lakeParameters -Apply

    Executes the deployment after confirmation.

    .OUTPUTS
    Bower.DeploymentPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')]
        [string] $CodeS3Bucket,

        [Parameter(Mandatory)]
        [ValidateLength(1, 1024)]
        [string] $CodeS3Key,

        [Parameter(Mandatory)]
        [ValidateCount(1, 32)]
        [ValidatePattern('^arn:aws[a-z-]*:(iam|sts)::[0-9]{12}:[A-Za-z0-9+=,.@_/-]+$')]
        [string[]] $AllowedInvokerPrincipalArns,

        [Parameter(Mandatory)]
        [ValidateRange(7, 3653)]
        [int] $RetentionDays,

        [ValidateSet('function-url', 'invoke')]
        [string] $IngressMode = 'function-url',

        [ValidatePattern('^[^\s]{1,64}$')]
        [string] $InvokeProducer,

        [ValidatePattern('^arn:aws[a-z-]*:cloudtrail:[a-z0-9-]+:[0-9]{12}:channel/[A-Za-z0-9-]+$')]
        [string] $ExistingChannelArn,

        [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,127}$')]
        [string] $StackName = 'bower-cloudtrail-lake',

        [ValidatePattern('^[a-z]{2}(-[a-z]+)+-\d+$')]
        [string] $Region = 'ap-southeast-2',

        [ValidateNotNullOrEmpty()]
        [string] $ProfileName,

        [ValidateSet('CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND')]
        [string[]] $Capability = @('CAPABILITY_IAM', 'CAPABILITY_AUTO_EXPAND'),

        [string] $TemplatePath,

        [string] $AwsPath,

        [switch] $Apply
    )

    try {
        if ($IngressMode -eq 'invoke' -and -not $InvokeProducer) {
            throw [System.ArgumentException]::new('-IngressMode invoke requires -InvokeProducer.')
        }
        if ($IngressMode -eq 'function-url' -and $InvokeProducer) {
            throw [System.ArgumentException]::new('-InvokeProducer is only used with -IngressMode invoke; deploy a separate invoke stack.')
        }
        $template = Resolve-BowerTemplatePath -Path $TemplatePath -Default 'deploy/aws/bower-aws-cloudtrail-lake.yaml'
        $parameters = [ordered]@{
            CodeS3Bucket                = $CodeS3Bucket
            CodeS3Key                   = $CodeS3Key
            AllowedInvokerPrincipalArns = @($AllowedInvokerPrincipalArns)
            RetentionDays               = $RetentionDays
            IngressMode                 = $IngressMode
        }
        if ($InvokeProducer) {
            $parameters.InvokeProducer = $InvokeProducer
        }
        if ($ExistingChannelArn) {
            $parameters.ExistingChannelArn = $ExistingChannelArn
        }
        $checks = if ($IngressMode -eq 'function-url') {
            @(
                'Confirm the Function URL AuthType is AWS_IAM and only the listed principals may invoke it.',
                'Apply deploy/aws/policies/bower-lambda-deny-direct-invoke-scp.json (SCP or permissions boundary) with the FunctionName output; verify a direct aws lambda invoke is denied.'
            )
        }
        else {
            @('Confirm only the listed principals hold lambda:InvokeFunction; every payload is attributed to the invoke producer.')
        }

        $target = "stack '$StackName' in $Region"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, 'Deploy Bower CloudTrail Lake stack (aws cloudformation deploy)')) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Create change set (aws cloudformation deploy --no-execute-changeset)')
            'Preview'
        }
        else {
            'Plan'
        }

        $remaining = @("Review the change set: aws cloudformation describe-change-set --stack-name $StackName --change-set-name <name> --region $Region") +
            $checks + @('Send a canary with Send-BowerSecurityEvent -Target Lambda and query it in CloudTrail Lake.')
        Invoke-BowerCloudFormationDeployment -Name 'aws-cloudtrail-lake' -TemplatePath $template -StackName $StackName -Region $Region `
            -ProfileName $ProfileName -Parameters $parameters -Capability $Capability -Mode $mode -AwsPath $AwsPath -RemainingChecks $remaining
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
