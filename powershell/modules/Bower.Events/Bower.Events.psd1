@{
    RootModule           = 'Bower.Events.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'cc45d0e2-2366-4e8f-bea0-07f39946dd57'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Build, validate and send Bower security event envelopes to a Bower collector, the Bower Azure Function or the Bower CloudTrail Lake Lambda.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'New-BowerSecurityEvent',
        'Send-BowerSecurityEvent',
        'Test-BowerSecurityEvent'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Sentinel', 'Telemetry')
        }
    }
}
