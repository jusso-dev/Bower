@{
    RootModule           = 'Bower.Management.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'da1d7005-5888-4701-b616-4040b1ac96df'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Operate a Bower management API: collector lifecycle, audit, jobs and versioned privacy profile review and assignment, with Entra tokens held in memory only.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Approve-BowerCollector',
        'Approve-BowerPrivacyProfileVersion',
        'Clear-BowerCollectorPrivacyProfile',
        'Connect-BowerManagement',
        'Deny-BowerCollector',
        'Deny-BowerPrivacyProfileVersion',
        'Disconnect-BowerManagement',
        'Get-BowerAuditEvent',
        'Get-BowerCollector',
        'Get-BowerJob',
        'Get-BowerManagementConnection',
        'Get-BowerPrivacyProfileAssignment',
        'Get-BowerPrivacyProfileVersion',
        'Invoke-BowerManagementRequest',
        'Invoke-BowerPrivacyProfilePreview',
        'Resume-BowerCollector',
        'Revoke-BowerCollector',
        'Set-BowerCollectorPrivacyProfile',
        'Start-BowerJob',
        'Submit-BowerPrivacyProfile',
        'Suspend-BowerCollector'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Entra', 'Management')
        }
    }
}
