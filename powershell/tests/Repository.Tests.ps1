BeforeDiscovery {
    $modulesRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../modules'))
    $script:ModuleNames = @('Bower.Events', 'Bower.Management', 'Bower.Deployment', 'Bower.Privacy', 'Bower.Policy')
    $script:ModuleCases = @($script:ModuleNames + 'Bower' | ForEach-Object { @{ Name = $_ } })
    $script:FunctionCases = foreach ($name in $script:ModuleNames) {
        foreach ($file in Get-ChildItem -Path (Join-Path $modulesRoot "$name/Public") -Filter *.ps1) {
            @{ Module = $name; Function = $file.BaseName }
        }
    }
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:ModuleNames = @('Bower.Events', 'Bower.Management', 'Bower.Deployment', 'Bower.Privacy', 'Bower.Policy')
    foreach ($name in $script:ModuleNames) {
        Import-BowerTestModule -Name $name
    }
    $script:Source = Get-ChildItem -Path $script:ModulesRoot -Include *.ps1, *.psm1, *.psd1 -Recurse -File
}

Describe 'Module manifest <Name>' -ForEach $script:ModuleCases {
    BeforeAll {
        $script:ManifestPath = Join-Path $script:ModulesRoot "$Name/$Name.psd1"
        $script:Manifest = Import-PowerShellDataFile -Path $script:ManifestPath
    }

    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'targets PowerShell 7.4+ Core at version 0.1.0' {
        $script:Manifest.ModuleVersion | Should -Be '0.1.0'
        $script:Manifest.PowerShellVersion | Should -Be '7.4'
        $script:Manifest.CompatiblePSEditions | Should -Be @('Core')
    }

    It 'exports an explicit function list with no wildcards' {
        $script:Manifest.FunctionsToExport.Count | Should -BeGreaterThan 0
        $script:Manifest.FunctionsToExport | Where-Object { $_ -match '[*?]' } | Should -BeNullOrEmpty
        $script:Manifest.CmdletsToExport | Should -BeNullOrEmpty
        $script:Manifest.VariablesToExport | Should -BeNullOrEmpty
        $script:Manifest.AliasesToExport | Should -BeNullOrEmpty
        $script:Manifest.ContainsKey('CmdletsToExport') | Should -BeTrue
        $script:Manifest.ContainsKey('VariablesToExport') | Should -BeTrue
        $script:Manifest.ContainsKey('AliasesToExport') | Should -BeTrue
    }

    It 'exports exactly the public functions' {
        $expected = if ($Name -eq 'Bower') {
            foreach ($module in $script:ModuleNames) { Get-ChildItem -Path (Join-Path $script:ModulesRoot "$module/Public") -Filter *.ps1 }
        }
        else {
            Get-ChildItem -Path (Join-Path $script:ModulesRoot "$Name/Public") -Filter *.ps1
        }
        @($script:Manifest.FunctionsToExport | Sort-Object) | Should -Be @($expected.BaseName | Sort-Object)
    }
}

Describe 'Bower meta-module' {
    It 'declares the five modules as nested modules' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:ModulesRoot 'Bower/Bower.psd1')
        $manifest.NestedModules | Should -Be @('../Bower.Events/Bower.Events.psd1', '../Bower.Management/Bower.Management.psd1', '../Bower.Deployment/Bower.Deployment.psd1', '../Bower.Privacy/Bower.Privacy.psd1', '../Bower.Policy/Bower.Policy.psd1')
    }

    It 'imports every command in one line' {
        $commands = pwsh -NoProfile -NonInteractive -Command "Import-Module '$(Join-Path $script:ModulesRoot 'Bower/Bower.psd1')' -ErrorAction Stop; (Get-Command -Module Bower).Name | Sort-Object"
        $LASTEXITCODE | Should -Be 0
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:ModulesRoot 'Bower/Bower.psd1')
        @($commands) | Should -Be @($manifest.FunctionsToExport | Sort-Object)
    }
}

Describe 'Public function <Function>' -ForEach $script:FunctionCases {
    BeforeAll {
        $script:Command = Get-Command -Module $Module -Name $Function -ErrorAction Stop
        $script:Help = Get-Help -Name "$Module\$Function" -Full
        $script:Common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
    }

    It 'is an advanced function' {
        $script:Command.CmdletBinding | Should -BeTrue
    }

    It 'uses an approved verb' {
        (Get-Verb).Verb | Should -Contain $script:Command.Verb
    }

    It 'has comment-based help with a synopsis, description and examples' {
        $script:Help.Synopsis | Should -Not -BeNullOrEmpty
        $script:Help.Synopsis | Should -Not -BeLike "*$Function *[<CommonParameters>]*"
        ($script:Help.Description | Out-String).Trim() | Should -Not -BeNullOrEmpty
        @($script:Help.Examples.Example).Count | Should -BeGreaterOrEqual 1
        foreach ($example in @($script:Help.Examples.Example)) {
            $example.Code | Should -Not -BeNullOrEmpty
        }
    }

    It 'documents every parameter' {
        foreach ($parameter in $script:Command.Parameters.Keys | Where-Object { $_ -notin $script:Common }) {
            $parameterHelp = $script:Help.Parameters.Parameter | Where-Object Name -EQ $parameter
            ($parameterHelp.Description | Out-String).Trim() | Should -Not -BeNullOrEmpty -Because "parameter -$parameter of $Function needs help"
        }
    }

    It 'never accepts tokens or secrets as plain strings' {
        foreach ($parameter in $script:Command.Parameters.Values) {
            if ($parameter.Name -match '(?i)(token|secret|password|credential)' -and $parameter.Name -ne 'TokenProvider') {
                $parameter.ParameterType | Should -Be ([securestring]) -Because "-$($parameter.Name) carries a secret"
            }
        }
    }
}

Describe 'State-changing commands' {
    It '<Name> supports ShouldProcess with ConfirmImpact <Impact>' -ForEach @(
        @{ Name = 'Approve-BowerCollector'; Impact = 'Medium' }
        @{ Name = 'Deny-BowerCollector'; Impact = 'Medium' }
        @{ Name = 'Suspend-BowerCollector'; Impact = 'Medium' }
        @{ Name = 'Resume-BowerCollector'; Impact = 'Medium' }
        @{ Name = 'Revoke-BowerCollector'; Impact = 'High' }
        @{ Name = 'Start-BowerJob'; Impact = 'Medium' }
        @{ Name = 'Submit-BowerPrivacyProfile'; Impact = 'Medium' }
        @{ Name = 'Approve-BowerPrivacyProfileVersion'; Impact = 'Medium' }
        @{ Name = 'Deny-BowerPrivacyProfileVersion'; Impact = 'Medium' }
        @{ Name = 'Set-BowerCollectorPrivacyProfile'; Impact = 'High' }
        @{ Name = 'Clear-BowerCollectorPrivacyProfile'; Impact = 'High' }
        @{ Name = 'Send-BowerSecurityEvent'; Impact = 'Low' }
        @{ Name = 'New-BowerEntraApplication'; Impact = 'High' }
        @{ Name = 'Deploy-BowerSentinelResource'; Impact = 'High' }
        @{ Name = 'Deploy-BowerAzureFunction'; Impact = 'High' }
        @{ Name = 'Deploy-BowerAwsLambda'; Impact = 'High' }
        @{ Name = 'New-BowerPolicy'; Impact = 'Medium' }
        @{ Name = 'Deploy-BowerAwsSecurity'; Impact = 'High' }
        @{ Name = 'Deploy-BowerGcpSecurity'; Impact = 'High' }
    ) {
        $command = Get-Command -Name $Name
        $binding = $command.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $binding.SupportsShouldProcess | Should -BeTrue
        $binding.ConfirmImpact | Should -Be $Impact
        $command.Parameters.Keys | Should -Contain 'WhatIf'
    }

    It '<Name> requires a reason' -ForEach @(
        @{ Name = 'Approve-BowerCollector' }, @{ Name = 'Deny-BowerCollector' }, @{ Name = 'Suspend-BowerCollector' },
        @{ Name = 'Resume-BowerCollector' }, @{ Name = 'Revoke-BowerCollector' }, @{ Name = 'Approve-BowerPrivacyProfileVersion' },
        @{ Name = 'Deny-BowerPrivacyProfileVersion' }, @{ Name = 'Set-BowerCollectorPrivacyProfile' }, @{ Name = 'Clear-BowerCollectorPrivacyProfile' }
    ) {
        $parameter = (Get-Command -Name $Name).Parameters['Reason']
        $parameter | Should -Not -BeNullOrEmpty
        ($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Not -Contain $false
    }

    It 'Deploy commands default to planning (an -Apply switch is required to mutate)' {
        foreach ($name in 'New-BowerEntraApplication', 'Deploy-BowerSentinelResource', 'Deploy-BowerAzureFunction', 'Deploy-BowerAwsLambda', 'Deploy-BowerAwsSecurity', 'Deploy-BowerGcpSecurity') {
            (Get-Command -Name $name).Parameters['Apply'].ParameterType | Should -Be ([switch])
        }
    }
}

Describe 'Source safety rules' {
    It 'never uses Invoke-Expression' {
        $script:Source | Select-String -Pattern '(?i)\b(Invoke-Expression|iex)\b' | Should -BeNullOrEmpty
    }

    It 'never disables TLS certificate validation' {
        $script:Source | Select-String -Pattern '(?i)(SkipCertificateCheck|ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|CheckCertificateRevocationList\s*=\s*\$false)' |
            Should -BeNullOrEmpty
    }

    It 'never converts plaintext with ConvertTo-SecureString -AsPlainText' {
        $script:Source | Select-String -Pattern '(?i)ConvertTo-SecureString' | Should -BeNullOrEmpty
    }

    It 'writes nothing to the host and sends no telemetry' {
        $script:Source | Select-String -Pattern '(?i)\bWrite-Host\b|ApplicationInsights|TelemetryClient' | Should -BeNullOrEmpty
    }

    It 'only references example or documented endpoints' {
        $urls = $script:Source | Select-String -Pattern 'https?://[^\s''"`)<>]+' -AllMatches | ForEach-Object { $_.Matches.Value }
        $allowed = '^https?://(127\.0\.0\.1|localhost|[a-z0-9.-]*example\.(gov\.au|test)|[a-z0-9-]+\.azurewebsites\.net|[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws|[a-z0-9.-]+\.ingest\.monitor\.azure\.com)([:/.,;]|$)'
        $urls | Where-Object { $_ -notmatch $allowed } | Should -BeNullOrEmpty
    }

    It 'keeps shared HTTP and token helpers identical in Bower.Events and Bower.Management' {
        foreach ($file in 'BowerHttp.ps1', 'BowerToken.ps1') {
            $events = Get-FileHash (Join-Path $script:ModulesRoot "Bower.Events/Private/Shared/$file")
            $management = Get-FileHash (Join-Path $script:ModulesRoot "Bower.Management/Private/Shared/$file")
            $events.Hash | Should -Be $management.Hash -Because "$file is shared"
        }
    }

    It 'keeps the shared CLI helper identical in Bower.Privacy, Bower.Policy and Bower.Deployment' {
        $privacy = (Get-FileHash (Join-Path $script:ModulesRoot 'Bower.Privacy/Private/Shared/BowerCli.ps1')).Hash
        foreach ($module in 'Bower.Deployment', 'Bower.Policy') {
            (Get-FileHash (Join-Path $script:ModulesRoot "$module/Private/Shared/BowerCli.ps1")).Hash | Should -Be $privacy -Because "$module shares it"
        }
    }

    It 'keeps the shared YAML helper identical in Bower.Privacy and Bower.Policy' {
        (Get-FileHash (Join-Path $script:ModulesRoot 'Bower.Privacy/Private/Shared/BowerYaml.ps1')).Hash |
            Should -Be (Get-FileHash (Join-Path $script:ModulesRoot 'Bower.Policy/Private/Shared/BowerYaml.ps1')).Hash
    }
}

Describe 'Envelope rules match schemas/envelope/security-event.schema.json' {
    BeforeAll {
        $script:Schema = Get-Content -Raw (Join-Path $script:RepositoryRoot 'schemas/envelope/security-event.schema.json') | ConvertFrom-Json -AsHashtable
        $script:Rules = InModuleScope Bower.Events {
            @{
                Version       = $script:EnvelopeSchemaVersion
                Properties    = $script:EnvelopeProperties
                Required      = $script:EnvelopeRequired
                Categories    = $script:EventCategories
                Results       = $script:EventResults
                Severities    = $script:EventSeverities
                ActorTypes    = $script:ActorTypes
                TypePattern   = $script:EventTypePattern
                Nested        = $script:NestedProperties
                NestedLimits  = $script:NestedStringLimits
            }
        }
    }

    It 'has the same version, properties and required fields' {
        $script:Rules.Version | Should -Be $script:Schema.properties.schemaVersion.const
        @($script:Rules.Properties | Sort-Object) | Should -Be @($script:Schema.properties.Keys | Sort-Object)
        @($script:Rules.Required | Sort-Object) | Should -Be @($script:Schema.required | Sort-Object)
    }

    It 'has the same enumerations and event type pattern' {
        $script:Rules.Categories | Should -Be $script:Schema.properties.eventCategory.enum
        $script:Rules.Results | Should -Be $script:Schema.properties.eventResult.enum
        $script:Rules.Severities | Should -Be $script:Schema.properties.eventSeverity.enum
        $script:Rules.ActorTypes | Should -Be $script:Schema['$defs'].actor.properties.type.enum
        $script:Rules.TypePattern | Should -Be $script:Schema.properties.eventType.pattern
    }

    It 'has the same nested properties and string limits' {
        foreach ($name in 'application', 'actor', 'target', 'source') {
            @($script:Rules.Nested[$name] | Sort-Object) | Should -Be @($script:Schema['$defs'][$name].properties.Keys | Sort-Object)
            foreach ($member in $script:Rules.NestedLimits[$name].Keys) {
                $script:Rules.NestedLimits[$name][$member] | Should -Be $script:Schema['$defs'][$name].properties[$member].maxLength -Because "$name.$member"
            }
        }
        @($script:Rules.Nested.request | Sort-Object) | Should -Be @($script:Schema.properties.request.properties.Keys | Sort-Object)
        foreach ($member in $script:Rules.NestedLimits.request.Keys) {
            $script:Rules.NestedLimits.request[$member] | Should -Be $script:Schema.properties.request.properties[$member].maxLength
        }
    }
}

Describe 'Invoke-BowerCli (unmocked)' {
    It 'separates stdout, stderr and the exit code without a shell' {
        $result = InModuleScope Bower.Privacy {
            Invoke-BowerCli -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', '[Console]::Out.WriteLine(''out''); [Console]::Error.WriteLine(''err''); exit 3')
        }
        $result.ExitCode | Should -Be 3
        $result.StdOut | Should -Be 'out'
        $result.StdErr | Should -Be 'err'
    }

    It 'passes arguments literally, without shell or PowerShell evaluation' {
        $script = Join-Path $TestDrive 'echo-args.ps1'
        Set-Content -LiteralPath $script -Value 'foreach ($item in $args) { [Console]::Out.WriteLine("<$item>") }'
        $result = InModuleScope Bower.Privacy -Parameters @{ Script = $script } {
            param($Script)
            Invoke-BowerCli -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-File', $Script, 'a b', '$(whoami); rm -rf /', '--flag=x y')
        }
        $result.ExitCode | Should -Be 0
        $result.StdOut -split [System.Environment]::NewLine | Should -Be @('<a b>', '<$(whoami); rm -rf />', '<--flag=x y>')
    }
}

Describe 'CI' {
    It 'runs the PowerShell build in GitHub Actions' {
        $workflow = Get-Content -Raw (Join-Path $script:RepositoryRoot '.github/workflows/ci.yml')
        $workflow | Should -Match 'pwsh -NoProfile -File powershell/build\.ps1'
    }
}
