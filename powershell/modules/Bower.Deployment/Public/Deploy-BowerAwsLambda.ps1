function Deploy-BowerAwsLambda {
    <#
    .SYNOPSIS
    Plans (default) or applies the Bower AWS Lambda stack from deploy/aws/bower-aws-lambda.yaml.

    .DESCRIPTION
    Wraps `aws cloudformation deploy`. By default it passes --no-execute-changeset, which
    creates a reviewable change set and executes nothing (for a new stack, CloudFormation
    shows it in REVIEW_IN_PROGRESS). -Apply executes the deployment only after
    ShouldProcess confirmation (ConfirmImpact High). -WhatIf runs nothing.

    The stack deploys the Rust Lambda (code from -CodeS3Bucket/-CodeS3Key). It writes to
    one destination with its execution role only: a CloudWatch Logs log group the stack
    creates (-Destination cloudwatch-logs, the default) or a CloudTrail Lake event data
    store through a custom integration channel (-Destination cloudtrail-lake; AWS closed
    CloudTrail Lake to new customers on 31 May 2026).

    It serves exactly one ingress: behind a Function URL with AuthType AWS_IAM
    (-IngressMode function-url, the default) or for direct Invoke attributed to
    -InvokeProducer (-IngressMode invoke). Deploy two stacks to offer both. For a Function
    URL stack, also apply deploy/aws/policies/bower-lambda-deny-direct-invoke-scp.json as
    an SCP or permissions-boundary Deny: resource policies cannot stop same-account
    principals with identity-policy lambda:InvokeFunction from invoking the function
    directly.

    .PARAMETER CodeS3Bucket
    S3 bucket holding the Lambda deployment package.

    .PARAMETER CodeS3Key
    S3 key of the Lambda deployment package.

    .PARAMETER AllowedInvokerPrincipalArns
    IAM principal ARNs allowed to invoke the function (through the URL, or directly for -IngressMode invoke).

    .PARAMETER Destination
    cloudwatch-logs (default) or cloudtrail-lake.

    .PARAMETER EventLogRetentionDays
    Retention of the Bower event log group in days (cloudwatch-logs). Default 365.

    .PARAMETER EventLogKmsKeyArn
    Optional customer managed KMS key ARN for the Bower event log group (cloudwatch-logs).

    .PARAMETER RetentionDays
    CloudTrail Lake event data store retention in days. Required with -Destination cloudtrail-lake.

    .PARAMETER ExistingChannelArn
    ChannelArn output of another Bower CloudTrail Lake stack in the same account (cloudtrail-lake).
    The stack then creates no event data store or channel (use it for the second, invoke stack).

    .PARAMETER ReservedConcurrency
    Reserved concurrent executions (template default 10). 0 reserves nothing: required on
    accounts whose Lambda limit is the default 10, which cannot reserve any.

    .PARAMETER IngressMode
    function-url (default) or invoke. One ingress per stack; there is no mixed mode.

    .PARAMETER InvokeProducer
    Producer id for direct Invoke payloads. Required with -IngressMode invoke, not allowed with function-url.

    .PARAMETER StackName
    Stack name. Default bower-lambda.

    .PARAMETER Region
    AWS region. Default ap-southeast-2 (Sydney).

    .PARAMETER ProfileName
    AWS CLI profile.

    .PARAMETER Capability
    CloudFormation capabilities to acknowledge. Default CAPABILITY_IAM (the Lambda role) and
    CAPABILITY_AUTO_EXPAND (the template uses the AWS::LanguageExtensions transform).

    .PARAMETER TemplatePath
    Template path. Defaults to deploy/aws/bower-aws-lambda.yaml in this repository.

    .PARAMETER AwsPath
    Path to the aws executable. Defaults to aws on PATH.

    .PARAMETER Apply
    Execute the deployment instead of only creating a change set. Requires confirmation.

    .EXAMPLE
    Deploy-BowerAwsLambda -CodeS3Bucket bower-artifacts -CodeS3Key lambda/bower-lambda-0.1.0.zip `
        -AllowedInvokerPrincipalArns arn:aws:iam::123456789012:role/bower-producer

    Creates a change set for a CloudWatch Logs stack without executing it.

    .EXAMPLE
    Deploy-BowerAwsLambda @lambdaParameters -Destination cloudtrail-lake -RetentionDays 365 -Apply

    Executes a CloudTrail Lake deployment after confirmation.

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

        [ValidateSet('cloudwatch-logs', 'cloudtrail-lake')]
        [string] $Destination = 'cloudwatch-logs',

        [ValidateSet(1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653)]
        [int] $EventLogRetentionDays,

        [ValidatePattern('^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$')]
        [string] $EventLogKmsKeyArn,

        [ValidateRange(7, 3653)]
        [int] $RetentionDays,

        [ValidatePattern('^arn:aws[a-z-]*:cloudtrail:[a-z0-9-]+:[0-9]{12}:channel/[A-Za-z0-9-]+$')]
        [string] $ExistingChannelArn,

        [ValidateRange(0, 1000)]
        [int] $ReservedConcurrency,

        [ValidateSet('function-url', 'invoke')]
        [string] $IngressMode = 'function-url',

        [ValidatePattern('^[^\s]{1,64}$')]
        [string] $InvokeProducer,

        [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,127}$')]
        [string] $StackName = 'bower-lambda',

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
        $lake = $Destination -eq 'cloudtrail-lake'
        $lakeOnly = @(@('RetentionDays', 'ExistingChannelArn') | Where-Object { $PSBoundParameters.ContainsKey($_) })
        $logsOnly = @(@('EventLogRetentionDays', 'EventLogKmsKeyArn') | Where-Object { $PSBoundParameters.ContainsKey($_) })
        if (-not $lake -and $lakeOnly) {
            throw [System.ArgumentException]::new("-$($lakeOnly[0]) is only used with -Destination cloudtrail-lake.")
        }
        if ($lake -and $logsOnly) {
            throw [System.ArgumentException]::new("-$($logsOnly[0]) is only used with -Destination cloudwatch-logs.")
        }
        if ($lake -and -not $PSBoundParameters.ContainsKey('RetentionDays')) {
            throw [System.ArgumentException]::new('-Destination cloudtrail-lake requires -RetentionDays.')
        }

        $template = Resolve-BowerTemplatePath -Path $TemplatePath -Default 'deploy/aws/bower-aws-lambda.yaml'
        $parameters = [ordered]@{
            CodeS3Bucket                = $CodeS3Bucket
            CodeS3Key                   = $CodeS3Key
            AllowedInvokerPrincipalArns = @($AllowedInvokerPrincipalArns)
            Destination                 = $Destination
            IngressMode                 = $IngressMode
        }
        if ($lake) {
            $parameters.RetentionDays = $RetentionDays
            if ($ExistingChannelArn) {
                $parameters.ExistingChannelArn = $ExistingChannelArn
            }
        }
        else {
            if ($PSBoundParameters.ContainsKey('EventLogRetentionDays')) {
                $parameters.EventLogRetentionDays = $EventLogRetentionDays
            }
            if ($EventLogKmsKeyArn) {
                $parameters.EventLogKmsKeyArn = $EventLogKmsKeyArn
            }
        }
        if ($PSBoundParameters.ContainsKey('ReservedConcurrency')) {
            $parameters.ReservedConcurrency = $ReservedConcurrency
        }
        if ($InvokeProducer) {
            $parameters.InvokeProducer = $InvokeProducer
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
        $proof = if ($lake) {
            'Send a canary with Send-BowerSecurityEvent -Target Lambda and query it in CloudTrail Lake.'
        }
        else {
            'Send a canary with Send-BowerSecurityEvent -Target Lambda and find its eventId in the EventLogGroupName output with CloudWatch Logs Insights.'
        }

        $target = "stack '$StackName' in $Region"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, "Deploy Bower AWS Lambda stack to $Destination (aws cloudformation deploy)")) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Create change set (aws cloudformation deploy --no-execute-changeset)')
            'Preview'
        }
        else {
            'Plan'
        }

        $remaining = @("Review the change set: aws cloudformation describe-change-set --stack-name $StackName --change-set-name <name> --region $Region") +
            $checks + @($proof)
        Invoke-BowerCloudFormationDeployment -Name 'aws-lambda' -TemplatePath $template -StackName $StackName -Region $Region `
            -ProfileName $ProfileName -Parameters $parameters -Capability $Capability -Mode $mode -AwsPath $AwsPath -RemainingChecks $remaining
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
