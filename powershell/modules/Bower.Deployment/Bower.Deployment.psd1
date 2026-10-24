@{
    RootModule           = 'Bower.Deployment.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '7eee5d77-4544-4d95-8e88-eebcf6aabc06'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Plan-first wrappers for Bower deployment assets: Entra app registrations, Sentinel Bicep, the Azure Function, AWS CloudFormation and GCP Terraform.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Deploy-BowerAwsLambda',
        'Deploy-BowerAwsSecurity',
        'Deploy-BowerAzureFunction',
        'Deploy-BowerGcpSecurity',
        'Deploy-BowerSentinelResource',
        'New-BowerEntraApplication'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Bicep', 'CloudFormation', 'Terraform')
        }
    }
}
