#Requires -Version 7.4
<#
.SYNOPSIS
Static analysis, manifest checks and Pester tests for the Bower PowerShell modules.

.DESCRIPTION
1. PSScriptAnalyzer over modules/ and this script with PSScriptAnalyzerSettings.psd1;
   any Warning or Error fails the build.
2. Test-ModuleManifest for every module manifest.
3. Pester 5 tests under tests/. External CLIs and HTTP calls are mocked; the tests never
   contact a real collector, management API or cloud.

Requires Pester 5.5+ and PSScriptAnalyzer 1.21+ (Install-Module -Scope CurrentUser).

.PARAMETER TestResultPath
Optional NUnit XML result file.

.EXAMPLE
pwsh -NoProfile -File powershell/build.ps1
#>
[CmdletBinding()]
param(
    [string] $TestResultPath
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$pester = Get-Module -ListAvailable -Name Pester | Where-Object Version -GE ([version]'5.5.0') | Sort-Object Version -Descending | Select-Object -First 1
$analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object Version -GE ([version]'1.21.0') | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or -not $analyzer) {
    throw 'Pester 5.5+ and PSScriptAnalyzer 1.21+ are required: Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser'
}
Import-Module $pester -Force
Import-Module $analyzer -Force

Write-Information "PSScriptAnalyzer $($analyzer.Version)" -InformationAction Continue
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
$findings = @(
    Invoke-ScriptAnalyzer -Path (Join-Path $root 'modules') -Recurse -Settings $settings
    Invoke-ScriptAnalyzer -Path $PSCommandPath -Settings $settings
    # The Windows installer also runs on Windows PowerShell 5.1 (Intune, ConfigMgr, GPO).
    Invoke-ScriptAnalyzer -Path (Join-Path $root '../deploy/installers/windows') -Recurse -Settings @{
        Severity = @('Error', 'Warning')
        Rules    = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.4') } }
    }
)
if ($findings.Count -gt 0) {
    $findings | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Information -InformationAction Continue
    throw "PSScriptAnalyzer reported $($findings.Count) finding(s)."
}
Write-Information 'PSScriptAnalyzer: 0 findings.' -InformationAction Continue

$manifests = @(Get-ChildItem -Path (Join-Path $root 'modules') -Filter '*.psd1' -Recurse -File |
        Where-Object { $_.BaseName -eq $_.Directory.Name })
foreach ($manifest in $manifests) {
    $module = Test-ModuleManifest -Path $manifest.FullName -ErrorAction Stop
    Write-Information ('Test-ModuleManifest: {0} {1} ({2} functions)' -f $module.Name, $module.Version, $module.ExportedFunctions.Count) -InformationAction Continue
}

Write-Information "Pester $($pester.Version)" -InformationAction Continue
$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path $root 'tests'
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Normal'
if ($TestResultPath) {
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.TestResult.OutputPath = $TestResultPath
}
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') {
    throw "Pester: $($result.FailedCount) failed, $($result.PassedCount) passed."
}
Write-Information ("Build passed: {0} analyzer findings, {1} manifests, {2} tests passed." -f $findings.Count, $manifests.Count, $result.PassedCount) -InformationAction Continue
