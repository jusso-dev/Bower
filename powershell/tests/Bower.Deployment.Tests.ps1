BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BowerTestModule -Name Bower.Deployment

    # External CLIs and Microsoft Graph are always mocked: these tests never reach a cloud.
    Mock -ModuleName Bower.Deployment Resolve-BowerCliPath { "/mock/bin/$Name" }
    Mock -ModuleName Bower.Deployment Invoke-BowerCli { [pscustomobject]@{ ExitCode = 0; StdOut = '{"status":"Succeeded","changes":[]}'; StdErr = '' } }
    Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand { throw "Unmocked Microsoft Graph call: $Name" }
}

Describe 'Deploy-BowerSentinelResource' {
    It 'runs az deployment group what-if by default against deploy/bicep/main.bicep' {
        $plan = Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity -Location australiaeast

        $plan.Mode | Should -Be 'Plan'
        $plan.Executed | Should -BeTrue
        $plan.MutationsApplied | Should -BeFalse
        $plan.Template | Should -Be 'deploy/bicep/main.bicep'
        $plan.TemplateSha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.PlanSha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.Result.status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq '/mock/bin/az' -and
            (Test-ArgumentSequence $ArgumentList @('deployment', 'group', 'what-if', '--resource-group', 'rg-sentinel', '--name', 'bower-sentinel', '--template-file')) -and
            $ArgumentList -contains 'workspaceName=law-sentinel' -and $ArgumentList -contains 'createIngestIdentity=true' -and
            $ArgumentList -contains 'location=australiaeast' -and $ArgumentList -contains 'publicNetworkAccess=Enabled' -and
            $ArgumentList -contains '--no-pretty-print' -and $ArgumentList -notcontains 'create' -and
            $ArgumentList[$ArgumentList.IndexOf('--template-file') + 1] -like '*deploy*bicep*main.bicep'
        }
    }

    It 'produces stable plan hashes for the same inputs' {
        $first = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -IngestPrincipalObjectId 4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c
        $second = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -IngestPrincipalObjectId 4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c
        $other = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-2 -IngestPrincipalObjectId 4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c
        $first.PlanSha256 | Should -Be $second.PlanSha256
        $first.PlanSha256 | Should -Not -Be $other.PlanSha256
        $first.Parameters.ingestPrincipalObjectId | Should -Be '4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c'
    }

    It 'runs nothing with -WhatIf' {
        $plan = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -WhatIf
        $plan.Mode | Should -Be 'Preview'
        $plan.Executed | Should -BeFalse
        $plan.Commands[0] | Should -BeLike 'az deployment group what-if *'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'deploys only with -Apply and confirmation' {
        $plan = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -Apply -Confirm:$false
        $plan.Mode | Should -Be 'Apply'
        $plan.MutationsApplied | Should -BeTrue
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            (Test-ArgumentSequence $ArgumentList @('deployment', 'group', 'create')) -and $ArgumentList -notcontains 'what-if'
        }
    }

    It 'runs nothing with -Apply -WhatIf' {
        (Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -Apply -WhatIf).Mode | Should -Be 'Preview'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'passes the subscription when given' {
        Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -SubscriptionId 00000000-0000-0000-0000-000000000001 | Out-Null
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -ParameterFilter { Test-ArgumentSequence $ArgumentList @('--subscription', '00000000-0000-0000-0000-000000000001') }
    }

    It 'validates inputs like plan_ingestion.py' {
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName 'x' -CreateIngestIdentity } | Should -Throw '*3-63 letters*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -Location 'Australia East' } | Should -Throw '*Azure region identifier*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -IngestPrincipalObjectId ([guid]::Empty) } | Should -Throw '*zero GUID*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -FederationIssuer https://issuer.example } | Should -Throw '*both exact issuer and subject*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -FederationIssuer http://issuer.example -FederationSubject s } | Should -Throw '*HTTPS issuer*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -FederationIssuer https://issuer.example -FederationSubject 'system:*' } | Should -Throw '*bounded exact subject*'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'passes the Private Link scope and endpoint subnet only when given' {
        $subnet = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-dmz/subnets/relay'
        $plan = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity `
            -PublicNetworkAccess Disabled -PrivateLinkScopeName ampls-bower -PrivateEndpointSubnetId $subnet
        $plan.Parameters.privateLinkScopeName | Should -Be 'ampls-bower'
        $plan.Parameters.privateEndpointSubnetId | Should -Be $subnet
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains 'publicNetworkAccess=Disabled' -and $ArgumentList -contains 'privateLinkScopeName=ampls-bower' -and
            $ArgumentList -contains "privateEndpointSubnetId=$subnet" -and $ArgumentList -notcontains 'create'
        }

        $plain = Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity
        $plain.Parameters.Contains('privateLinkScopeName') | Should -BeFalse
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -PrivateEndpointSubnetId $subnet } | Should -Throw '*requires -PrivateLinkScopeName*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -PrivateLinkScopeName 'bad name' } | Should -Throw '*Private Link scope name*'
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -PrivateLinkScopeName ampls -PrivateEndpointSubnetId 'subnet-1' } | Should -Throw '*full subnet resource ID*'
    }

    It 'requires exactly one ingestion identity choice' {
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity -IngestPrincipalObjectId 4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c } | Should -Throw
    }

    It 'propagates az failures with bounded error output' {
        Mock -ModuleName Bower.Deployment Invoke-BowerCli { [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'ERROR: (AuthorizationFailed) The client does not have authorization.' } }
        { Deploy-BowerSentinelResource -ResourceGroupName rg -WorkspaceName law-1 -CreateIngestIdentity } |
            Should -Throw '*az deployment group failed with exit code 1: ERROR: (AuthorizationFailed)*'
    }
}

Describe 'Deploy-BowerAzureFunction' {
    BeforeAll {
        $script:FunctionTemplate = Join-Path $TestDrive 'function.bicep'
        Set-Content -LiteralPath $script:FunctionTemplate -Value "param location string`n"
        $script:ScopesFile = Join-Path $TestDrive 'producer-scopes.json'
        Set-Content -LiteralPath $script:ScopesFile -Value '[ { "producer": "app-1", "application": { "name": "payroll" } } ]'
        $script:FunctionParameters = @{
            ProducerScopesPath    = $script:ScopesFile
            ResourceGroupName     = 'rg-bower'
            Location              = 'australiaeast'
            DcrResourceId         = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-sentinel/providers/Microsoft.Insights/dataCollectionRules/bower-dcr'
            LogsIngestionEndpoint = 'https://bower-dce.australiaeast-1.ingest.monitor.azure.com'
            EntraTenantId         = '11111111-2222-3333-4444-555555555555'
            EntraAudience         = 'api://bower-function'
            TemplatePath          = $script:FunctionTemplate
        }
    }

    It 'plans with every template parameter' {
        $plan = Deploy-BowerAzureFunction @script:FunctionParameters -UserAssignedIdentityResourceId '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/bower-ingest'
        $plan.Mode | Should -Be 'Plan'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            (Test-ArgumentSequence $ArgumentList @('deployment', 'group', 'what-if', '--resource-group', 'rg-bower')) -and
            $ArgumentList -contains 'location=australiaeast' -and $ArgumentList -contains 'namePrefix=bower' -and
            $ArgumentList -contains 'dcrResourceId=/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-sentinel/providers/Microsoft.Insights/dataCollectionRules/bower-dcr' -and
            $ArgumentList -contains 'logsIngestionEndpoint=https://bower-dce.australiaeast-1.ingest.monitor.azure.com' -and
            $ArgumentList -contains 'streamName=Custom-BowerSecurity' -and
            $ArgumentList -contains 'entraTenantId=11111111-2222-3333-4444-555555555555' -and
            $ArgumentList -contains 'entraAudience=api://bower-function' -and
            $ArgumentList -contains 'producerScopesJson=[{"producer":"app-1","application":{"name":"payroll"}}]' -and
            $ArgumentList -contains 'producerClaim=oid' -and
            $ArgumentList -contains 'userAssignedIdentityResourceId=/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/bower-ingest'
        }
    }

    It 'omits the optional identity when not given' {
        (Deploy-BowerAzureFunction @script:FunctionParameters).Parameters.Contains('userAssignedIdentityResourceId') | Should -BeFalse
    }

    It 'passes the packaged privacy profile path and rejects invalid producer scopes' {
        (Deploy-BowerAzureFunction @script:FunctionParameters -PrivacyProfilePath config/privacy.yaml).Parameters.privacyProfilePath |
            Should -Be 'config/privacy.yaml'
        $badScopes = Join-Path $TestDrive 'bad-scopes.json'
        Set-Content -LiteralPath $badScopes -Value '{ not json'
        $bad = $script:FunctionParameters.Clone()
        $bad.ProducerScopesPath = $badScopes
        { Deploy-BowerAzureFunction @bad } | Should -Throw '*not valid JSON*'
        Set-Content -LiteralPath $badScopes -Value '{ "producer": "app-1" }'
        { Deploy-BowerAzureFunction @bad } | Should -Throw '*JSON array*'
    }

    It 'applies only with -Apply and confirmation' {
        Deploy-BowerAzureFunction @script:FunctionParameters -WhatIf | Out-Null
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
        (Deploy-BowerAzureFunction @script:FunctionParameters -Apply -Confirm:$false).Mode | Should -Be 'Apply'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { Test-ArgumentSequence $ArgumentList @('deployment', 'group', 'create') }
    }

    It 'validates resource IDs and the ingestion endpoint' {
        $bad = $script:FunctionParameters.Clone()
        $bad.DcrResourceId = '/subscriptions/x/resourceGroups/rg'
        { Deploy-BowerAzureFunction @bad } | Should -Throw
        $bad = $script:FunctionParameters.Clone()
        $bad.LogsIngestionEndpoint = 'http://dce.example'
        { Deploy-BowerAzureFunction @bad } | Should -Throw '*https*'
    }

    It 'explains how to proceed when the default template is not present' {
        $parameters = $script:FunctionParameters.Clone()
        $parameters.Remove('TemplatePath')
        Mock -ModuleName Bower.Deployment Resolve-Path { $null } -ParameterFilter { $LiteralPath -like '*azure-function*main.bicep' }
        { Deploy-BowerAzureFunction @parameters } | Should -Throw '*was not found. Pass -TemplatePath*'
    }
}

Describe 'Deploy-BowerAwsLambda' {
    BeforeAll {
        $script:LambdaTemplate = Join-Path $TestDrive 'lambda.yaml'
        Set-Content -LiteralPath $script:LambdaTemplate -Value "AWSTemplateFormatVersion: '2010-09-09'`n"
        $script:LambdaParameters = @{
            CodeS3Bucket                = 'bower-artifacts'
            CodeS3Key                   = 'lambda/bower-lambda-0.1.0.zip'
            AllowedInvokerPrincipalArns = @('arn:aws:iam::123456789012:role/bower-producer', 'arn:aws:iam::123456789012:role/bower-ops')
            TemplatePath                = $script:LambdaTemplate
        }
        $script:LakeParameters = $script:LambdaParameters.Clone()
        $script:LakeParameters.Destination = 'cloudtrail-lake'
        $script:LakeParameters.RetentionDays = 365
    }

    It 'creates a CloudWatch Logs change set without executing it by default' {
        $plan = Deploy-BowerAwsLambda @script:LambdaParameters -EventLogRetentionDays 731
        $plan.Mode | Should -Be 'Plan'
        $plan.MutationsApplied | Should -BeFalse
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq '/mock/bin/aws' -and
            (Test-ArgumentSequence $ArgumentList @('cloudformation', 'deploy', '--stack-name', 'bower-lambda', '--template-file')) -and
            (Test-ArgumentSequence $ArgumentList @('--region', 'ap-southeast-2')) -and
            $ArgumentList -contains 'CodeS3Bucket=bower-artifacts' -and $ArgumentList -contains 'CodeS3Key=lambda/bower-lambda-0.1.0.zip' -and
            $ArgumentList -contains 'AllowedInvokerPrincipalArns=arn:aws:iam::123456789012:role/bower-producer,arn:aws:iam::123456789012:role/bower-ops' -and
            $ArgumentList -contains 'Destination=cloudwatch-logs' -and
            $ArgumentList -contains 'EventLogRetentionDays=731' -and
            -not ($ArgumentList | Where-Object { $_ -like 'RetentionDays=*' -or $_ -like 'ExistingChannelArn=*' }) -and
            $ArgumentList -contains 'IngressMode=function-url' -and
            -not ($ArgumentList | Where-Object { $_ -like 'InvokeProducer=*' }) -and
            (Test-ArgumentSequence $ArgumentList @('--capabilities', 'CAPABILITY_IAM', 'CAPABILITY_AUTO_EXPAND')) -and
            $ArgumentList -contains '--no-execute-changeset'
        }
        $plan.RemainingChecks -join ' ' | Should -BeLike '*bower-lambda-deny-direct-invoke-scp.json*'
        $plan.RemainingChecks -join ' ' | Should -BeLike '*CloudWatch Logs Insights*'
    }

    It 'plans a CloudTrail Lake stack with its retention' {
        $plan = Deploy-BowerAwsLambda @script:LakeParameters
        $plan.RemainingChecks -join ' ' | Should -BeLike '*query it in CloudTrail Lake*'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains 'Destination=cloudtrail-lake' -and $ArgumentList -contains 'RetentionDays=365' -and
            -not ($ArgumentList | Where-Object { $_ -like 'EventLog*' })
        }
    }

    It 'plans a separate direct-invoke stack with its producer' {
        $channel = 'arn:aws:cloudtrail:ap-southeast-2:123456789012:channel/0123abcd-89ab-cdef-0123-456789abcdef'
        $plan = Deploy-BowerAwsLambda @script:LakeParameters -IngressMode invoke -InvokeProducer batch-forwarder `
            -StackName bower-lambda-invoke -ExistingChannelArn $channel
        $plan.Mode | Should -Be 'Plan'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains 'IngressMode=invoke' -and $ArgumentList -contains 'InvokeProducer=batch-forwarder' -and
            $ArgumentList -contains "ExistingChannelArn=$channel" -and
            (Test-ArgumentSequence $ArgumentList @('--stack-name', 'bower-lambda-invoke'))
        }
    }

    It 'rejects mixed or incomplete ingress settings' {
        { Deploy-BowerAwsLambda @script:LambdaParameters -IngressMode both } | Should -Throw
        { Deploy-BowerAwsLambda @script:LambdaParameters -IngressMode invoke } | Should -Throw '*requires -InvokeProducer*'
        { Deploy-BowerAwsLambda @script:LambdaParameters -InvokeProducer batch-forwarder } | Should -Throw '*only used with -IngressMode invoke*'
        { Deploy-BowerAwsLambda @script:LakeParameters -ExistingChannelArn 'arn:aws:sqs:x' } | Should -Throw
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'rejects settings that belong to the other destination' {
        { Deploy-BowerAwsLambda @script:LambdaParameters -RetentionDays 365 } | Should -Throw '*-RetentionDays is only used with -Destination cloudtrail-lake*'
        $channel = 'arn:aws:cloudtrail:ap-southeast-2:123456789012:channel/0123abcd-89ab-cdef-0123-456789abcdef'
        { Deploy-BowerAwsLambda @script:LambdaParameters -ExistingChannelArn $channel } | Should -Throw '*only used with -Destination cloudtrail-lake*'
        { Deploy-BowerAwsLambda @script:LakeParameters -EventLogRetentionDays 365 } | Should -Throw '*only used with -Destination cloudwatch-logs*'
        $noRetention = $script:LakeParameters.Clone(); $noRetention.Remove('RetentionDays')
        { Deploy-BowerAwsLambda @noRetention } | Should -Throw '*requires -RetentionDays*'
        { Deploy-BowerAwsLambda @script:LambdaParameters -Destination s3 } | Should -Throw
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'executes only with -Apply and confirmation' {
        (Deploy-BowerAwsLambda @script:LambdaParameters -Apply -Confirm:$false).Mode | Should -Be 'Apply'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { $ArgumentList -notcontains '--no-execute-changeset' }
    }

    It 'runs nothing with -WhatIf' {
        (Deploy-BowerAwsLambda @script:LambdaParameters -WhatIf).Commands[0] | Should -BeLike 'aws cloudformation deploy *--no-execute-changeset*'
        (Deploy-BowerAwsLambda @script:LambdaParameters -Apply -WhatIf).Executed | Should -BeFalse
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'passes ReservedConcurrency only when given, including 0' {
        Deploy-BowerAwsLambda @script:LambdaParameters | Out-Null
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            -not ($ArgumentList | Where-Object { $_ -like 'ReservedConcurrency=*' })
        }
        Deploy-BowerAwsLambda @script:LambdaParameters -ReservedConcurrency 0 | Out-Null
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { $ArgumentList -contains 'ReservedConcurrency=0' }
        { Deploy-BowerAwsLambda @script:LambdaParameters -ReservedConcurrency 1001 } | Should -Throw
    }

    It 'passes the AWS profile when given' {
        Deploy-BowerAwsLambda @script:LambdaParameters -ProfileName bower-admin -Region ap-southeast-4 | Out-Null
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -ParameterFilter {
            (Test-ArgumentSequence $ArgumentList @('--profile', 'bower-admin')) -and (Test-ArgumentSequence $ArgumentList @('--region', 'ap-southeast-4'))
        }
    }

    It 'validates principal ARNs, retention and KMS keys' {
        $bad = $script:LambdaParameters.Clone(); $bad.AllowedInvokerPrincipalArns = @('*')
        { Deploy-BowerAwsLambda @bad } | Should -Throw
        $bad = $script:LakeParameters.Clone(); $bad.RetentionDays = 1
        { Deploy-BowerAwsLambda @bad } | Should -Throw
        { Deploy-BowerAwsLambda @script:LambdaParameters -EventLogRetentionDays 2 } | Should -Throw
        { Deploy-BowerAwsLambda @script:LambdaParameters -EventLogKmsKeyArn 'alias/bower' } | Should -Throw
    }
}

Describe 'Deploy-BowerAwsSecurity' {
    It 'plans the existing security template with parameter overrides' {
        $plan = Deploy-BowerAwsSecurity -Template Security -ParameterOverride @{ RuleState = 'DISABLED'; QueueName = 'bower-sec' }
        $plan.Template | Should -Be 'deploy/aws/bower-aws-security.yaml'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            (Test-ArgumentSequence $ArgumentList @('--stack-name', 'bower-security')) -and
            (Test-ArgumentSequence $ArgumentList @('--parameter-overrides', 'QueueName=bower-sec', 'RuleState=DISABLED')) -and
            $ArgumentList -contains '--no-execute-changeset'
        }
    }

    It 'plans the global forwarder template' {
        (Deploy-BowerAwsSecurity -Template GlobalForwarder -Region us-east-1 -ParameterOverride @{ HomeEventBusArn = 'arn:aws:events:ap-southeast-2:123456789012:event-bus/default' }).Template |
            Should -Be 'deploy/aws/bower-aws-global-forwarder.yaml'
    }

    It 'rejects invalid parameter names' {
        { Deploy-BowerAwsSecurity -Template Security -ParameterOverride @{ 'Rule State' = 'x' } } | Should -Throw '*not a valid CloudFormation parameter name*'
    }
}

Describe 'Deploy-BowerGcpSecurity' {
    BeforeEach {
        $script:VarFile = Join-Path $TestDrive 'prod.tfvars'
        Set-Content -LiteralPath $script:VarFile -Value 'project_id = "bower-test"'
        $script:PlanFile = Join-Path $TestDrive "plan-$([guid]::NewGuid()).tfplan"
    }

    It 'runs terraform init and plan with an output plan file' {
        $plan = Deploy-BowerGcpSecurity -VarFile $script:VarFile -PlanFile $script:PlanFile
        $plan.Mode | Should -Be 'Plan'
        $plan.Commands.Count | Should -Be 2
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { $ArgumentList[1] -eq 'init' -and $ArgumentList -contains '-input=false' }
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq '/mock/bin/terraform' -and $ArgumentList[0] -like '-chdir=*deploy*gcp' -and $ArgumentList[1] -eq 'plan' -and
            $ArgumentList -contains "-out=$script:PlanFile" -and ($ArgumentList | Where-Object { $_ -like '-var-file=*prod.tfvars' })
        }
    }

    It 'refuses to overwrite an existing plan file' {
        Set-Content -LiteralPath $script:PlanFile -Value 'old'
        { Deploy-BowerGcpSecurity -VarFile $script:VarFile -PlanFile $script:PlanFile } | Should -Throw '*already exists*'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }

    It 'applies only a reviewed plan file after confirmation' {
        { Deploy-BowerGcpSecurity -PlanFile $script:PlanFile -Apply -Confirm:$false } | Should -Throw '*was not found*'
        Set-Content -LiteralPath $script:PlanFile -Value 'reviewed'
        (Deploy-BowerGcpSecurity -PlanFile $script:PlanFile -Apply -Confirm:$false).Mode | Should -Be 'Apply'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { $ArgumentList[1] -eq 'apply' -and $ArgumentList[-1] -eq $script:PlanFile }
    }

    It 'runs nothing with -WhatIf' {
        (Deploy-BowerGcpSecurity -VarFile $script:VarFile -PlanFile $script:PlanFile -WhatIf).Executed | Should -BeFalse
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerCli -Times 0
    }
}

Describe 'New-BowerEntraApplication' {
    It 'plans both registrations from the checked-in manifests without calling Graph' {
        $plan = New-BowerEntraApplication -RedirectUri https://bower.example.gov.au, http://localhost:5173

        $plan.Mode | Should -Be 'Plan'
        $plan.Executed | Should -BeFalse
        $plan.CredentialsCreated | Should -BeFalse
        $plan.ApiApplication.signInAudience | Should -Be 'AzureADMyOrg'
        $plan.ApiApplication.Contains('identifierUris') | Should -BeFalse
        @($plan.ApiApplication.appRoles).value | Should -Be @('Bower.Viewer', 'Bower.Operator', 'Bower.Approver', 'Bower.Administrator', 'Bower.Collector')
        $plan.WebApplication.spa.redirectUris | Should -Be @('https://bower.example.gov.au', 'http://localhost:5173')
        $plan.WebApplication.requiredResourceAccess[0].resourceAccess[0].id | Should -Be '77fb48be-4622-4d5e-b5e6-0a30d8b67a32'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 0
    }

    It 'rejects insecure redirect URIs' {
        { New-BowerEntraApplication -RedirectUri http://bower.example.gov.au } | Should -Throw
        { New-BowerEntraApplication -RedirectUri 'https://bower.example.gov.au/?x=1' } | Should -Throw
    }

    It 'creates the API, its service principal, then the SPA with -Apply' {
        Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand { [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555' } } -ParameterFilter { $Name -eq 'Get-MgContext' }
        Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand {
            if ($Parameters.BodyParameter.displayName -eq 'Bower Management API') { [pscustomobject]@{ Id = 'api-object'; AppId = 'aaaaaaaa-0000-0000-0000-000000000001' } }
            else { [pscustomobject]@{ Id = 'web-object'; AppId = 'bbbbbbbb-0000-0000-0000-000000000002' } }
        } -ParameterFilter { $Name -eq 'New-MgApplication' }
        Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand { $null } -ParameterFilter { $Name -eq 'Update-MgApplication' }
        Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand { [pscustomobject]@{ Id = "sp-$($Parameters.AppId)" } } -ParameterFilter { $Name -eq 'New-MgServicePrincipal' }

        $plan = New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -TenantId 11111111-2222-3333-4444-555555555555 -Apply -Confirm:$false

        $plan.Mode | Should -Be 'Apply'
        $plan.Result.ApiScope | Should -Be 'api://aaaaaaaa-0000-0000-0000-000000000001/Bower.Access'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Update-MgApplication' -and $Parameters.ApplicationId -eq 'api-object' -and $Parameters.IdentifierUris[0] -eq 'api://aaaaaaaa-0000-0000-0000-000000000001'
        }
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'New-MgApplication' -and $Parameters.BodyParameter.displayName -eq 'Bower Management Web' -and
            $Parameters.BodyParameter.requiredResourceAccess[0].resourceAppId -eq 'aaaaaaaa-0000-0000-0000-000000000001'
        }
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 2 -Exactly -ParameterFilter { $Name -eq 'New-MgServicePrincipal' }
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 0 -ParameterFilter {
            $Parameters.BodyParameter -and ($Parameters.BodyParameter.Contains('passwordCredentials') -or $Parameters.BodyParameter.Contains('keyCredentials'))
        }
    }

    It 'refuses to create registrations in an unexpected tenant' {
        Mock -ModuleName Bower.Deployment Invoke-BowerGraphCommand { [pscustomobject]@{ TenantId = '99999999-2222-3333-4444-555555555555' } } -ParameterFilter { $Name -eq 'Get-MgContext' }
        { New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -TenantId 11111111-2222-3333-4444-555555555555 -Apply -Confirm:$false } |
            Should -Throw "*connected to tenant '99999999-2222-3333-4444-555555555555'*"
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 0 -ParameterFilter { $Name -eq 'New-MgApplication' }
    }

    It 'calls nothing with -Apply -WhatIf' {
        (New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -Apply -WhatIf).Mode | Should -Be 'Preview'
        Should -Invoke -ModuleName Bower.Deployment Invoke-BowerGraphCommand -Times 0
    }

    It 'refuses manifests that carry secrets' {
        $directory = Join-Path $TestDrive 'entra'
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        Copy-Item -Path (Join-Path $script:RepositoryRoot 'deploy/entra/spa-app-manifest.json') -Destination $directory
        $api = Get-Content (Join-Path $script:RepositoryRoot 'deploy/entra/api-app-manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        $api.passwordCredentials = @(@{ displayName = 'secret' })
        $api | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $directory 'api-app-manifest.json')
        { New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -ManifestDirectory $directory } | Should -Throw '*never carry client secrets*'
    }
}

