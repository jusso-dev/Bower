@{
    RootModule           = 'Bower.Privacy.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '3f51454e-18fd-4e0d-b8fa-b0b385deaecb'
    Author               = 'Bower contributors'
    CompanyName          = 'Bower'
    Copyright            = '(c) Bower contributors. Licensed under the repository LICENSE.'
    Description          = 'Local privacy profile tooling: validate with the bower CLI, author custom detectors and normalise secret field names.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'ConvertTo-BowerSecretFieldName',
        'New-BowerCustomDetector',
        'Test-BowerPrivacyProfile'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Bower', 'Security', 'Privacy', 'Redaction')
        }
    }
}
