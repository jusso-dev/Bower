# PSScriptAnalyzer settings for powershell/. build.ps1 fails on any Warning or Error.
@{
    Severity     = @('Error', 'Warning')
    IncludeDefaultRules = $true
    ExcludeRules = @()
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.4')
        }
        PSAvoidUsingCmdletAliases = @{
            AllowList = @()
        }
    }
}
