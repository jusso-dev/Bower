@{
    RootModule           = 'Bower.Policy.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '9c677710-b373-427d-9399-acc33aa81306'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Local telemetry policy tooling: author policies and validate and test them offline against sample events with the bower CLI.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'New-BowerPolicy',
        'Test-BowerPolicy',
        'Test-BowerPolicyEvent'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Policy', 'Sentinel')
        }
    }
}
