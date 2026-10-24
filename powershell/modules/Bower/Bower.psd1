@{
    ModuleVersion        = '0.1.0'
    GUID                 = 'ce1b7b59-0929-4ca2-9ed4-02cc201ebe55'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Bower PowerShell modules: Bower.Events, Bower.Management, Bower.Deployment and Bower.Privacy in one import.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    NestedModules        = @(
        '../Bower.Events/Bower.Events.psd1',
        '../Bower.Management/Bower.Management.psd1',
        '../Bower.Deployment/Bower.Deployment.psd1',
        '../Bower.Privacy/Bower.Privacy.psd1'
    )
    FunctionsToExport    = @(
        'Approve-BowerCollector',
        'Approve-BowerPrivacyProfileVersion',
        'Clear-BowerCollectorPrivacyProfile',
        'Connect-BowerManagement',
        'ConvertTo-BowerSecretFieldName',
        'Deny-BowerCollector',
        'Deny-BowerPrivacyProfileVersion',
        'Deploy-BowerAwsCloudTrailLake',
        'Deploy-BowerAwsSecurity',
        'Deploy-BowerAzureFunction',
        'Deploy-BowerGcpSecurity',
        'Deploy-BowerSentinelResource',
        'Disconnect-BowerManagement',
        'Get-BowerAuditEvent',
        'Get-BowerCollector',
        'Get-BowerJob',
        'Get-BowerManagementConnection',
        'Get-BowerPrivacyProfileAssignment',
        'Get-BowerPrivacyProfileVersion',
        'Invoke-BowerManagementRequest',
        'Invoke-BowerPrivacyProfilePreview',
        'New-BowerCustomDetector',
        'New-BowerEntraApplication',
        'New-BowerSecurityEvent',
        'Resume-BowerCollector',
        'Revoke-BowerCollector',
        'Send-BowerSecurityEvent',
        'Set-BowerCollectorPrivacyProfile',
        'Start-BowerJob',
        'Submit-BowerPrivacyProfile',
        'Suspend-BowerCollector',
        'Test-BowerPrivacyProfile',
        'Test-BowerSecurityEvent'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Sentinel')
        }
    }
}
