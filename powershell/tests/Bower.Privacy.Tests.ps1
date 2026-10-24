BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BowerTestModule -Name Bower.Privacy

    # The bower CLI is always mocked here; its real output shape is owned by the CLI.
    Mock -ModuleName Bower.Privacy Resolve-BowerCliPath { if ($Path) { $Path } else { "/mock/bin/$Name" } }
    Mock -ModuleName Bower.Privacy Invoke-BowerCli { throw "Unmocked bower call: $($ArgumentList -join ' ')" }

    $script:ValidSummary = [ordered]@{
        valid             = $true
        errors            = @()
        profileId         = 'contoso-app'
        version           = '1.2.0'
        contentHash       = 'sha256:' + ('a' * 64)
        customDetectors   = @(@{ id = 'custom.employee-id'; description = 'Employee numbers'; action = 'mask' })
        secretFieldNames  = 2
        detectorOverrides = 1
        fieldRules        = 3
    } | ConvertTo-Json -Depth 5
}

Describe 'Test-BowerPrivacyProfile (local)' {
    BeforeEach {
        $script:ProfilePath = Join-Path $TestDrive 'profile.yaml'
        Set-Content -LiteralPath $script:ProfilePath -Value 'kind: PrivacyProfile'
        Mock -ModuleName Bower.Privacy Invoke-BowerCli { [pscustomobject]@{ ExitCode = 0; StdOut = $script:ValidSummary; StdErr = '' } }
    }

    It 'runs bower privacy validate FILE and parses the JSON summary' {
        $result = Test-BowerPrivacyProfile -Path $script:ProfilePath

        $result.PSObject.TypeNames[0] | Should -Be 'Bower.PrivacyProfileValidation'
        $result.valid | Should -BeTrue
        $result.profileId | Should -Be 'contoso-app'
        $result.customDetectors[0].id | Should -Be 'custom.employee-id'
        $result.secretFieldNames | Should -Be 2
        $result.Source | Should -Be 'Local'
        $result.Path | Should -Be (Resolve-Path $script:ProfilePath).ProviderPath
        Should -Invoke -ModuleName Bower.Privacy Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq '/mock/bin/bower' -and $ArgumentList.Count -eq 3 -and
            $ArgumentList[0] -eq 'privacy' -and $ArgumentList[1] -eq 'validate' -and $ArgumentList[2] -eq (Resolve-Path $script:ProfilePath).ProviderPath
        }
    }

    It 'passes --hmac-key-file and --sample with resolved paths' {
        $key = Join-Path $TestDrive 'hmac.key'; Set-Content -LiteralPath $key -Value 'k'
        $sample = Join-Path $TestDrive 'sample.json'; Set-Content -LiteralPath $sample -Value '{}'
        Test-BowerPrivacyProfile -Path $script:ProfilePath -HmacKeyFile $key -SamplePath $sample | Out-Null
        Should -Invoke -ModuleName Bower.Privacy Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[3] -eq '--hmac-key-file' -and $ArgumentList[4] -eq (Resolve-Path $key).ProviderPath -and
            $ArgumentList[5] -eq '--sample' -and $ArgumentList[6] -eq (Resolve-Path $sample).ProviderPath
        }
    }

    It 'uses -BowerPath when given' {
        $bower = Join-Path $TestDrive 'bower'; Set-Content -LiteralPath $bower -Value ''
        Test-BowerPrivacyProfile -Path $script:ProfilePath -BowerPath $bower | Out-Null
        Should -Invoke -ModuleName Bower.Privacy Resolve-BowerCliPath -Times 1 -Exactly -ParameterFilter { $Name -eq 'bower' -and $Path -eq $bower }
        Should -Invoke -ModuleName Bower.Privacy Invoke-BowerCli -Times 1 -Exactly -ParameterFilter { $FilePath -eq $bower }
    }

    It 'returns an invalid result (not an error) when the CLI reports validation errors' {
        Mock -ModuleName Bower.Privacy Invoke-BowerCli {
            [pscustomobject]@{
                ExitCode = 1
                StdOut   = '{"valid":false,"errors":["Custom detector ''custom.employee-id'' did not match tests.match[0]."],"profileId":null}'
                StdErr   = ''
            }
        }
        $result = Test-BowerPrivacyProfile -Path $script:ProfilePath
        $result.valid | Should -BeFalse
        $result.errors | Should -Be @("Custom detector 'custom.employee-id' did not match tests.match[0].")
    }

    It 'fails with bounded stderr when the CLI does not return JSON' {
        Mock -ModuleName Bower.Privacy Invoke-BowerCli { [pscustomobject]@{ ExitCode = 2; StdOut = 'Usage: bower ...'; StdErr = 'Unknown command: privacy' } }
        { Test-BowerPrivacyProfile -Path $script:ProfilePath } | Should -Throw '*did not return a JSON summary (exit code 2): Unknown command: privacy*'
    }

    It 'fails clearly when the profile does not exist' {
        { Test-BowerPrivacyProfile -Path (Join-Path $TestDrive 'missing.yaml') } | Should -Throw "*Privacy profile '*missing.yaml' was not found*"
        Should -Invoke -ModuleName Bower.Privacy Invoke-BowerCli -Times 0
    }

    It 'fails clearly when bower is not on PATH' {
        Mock -ModuleName Bower.Privacy Resolve-BowerCliPath { throw [System.Management.Automation.CommandNotFoundException]::new("'bower' was not found on PATH. Install it or pass its path.") }
        { Test-BowerPrivacyProfile -Path $script:ProfilePath } | Should -Throw "*'bower' was not found on PATH*"
    }
}

Describe 'Test-BowerPrivacyProfile -Remote' {
    BeforeAll {
        Import-BowerTestModule -Name Bower.Management
        Mock -ModuleName Bower.Management Invoke-RestMethod { throw "Unmocked Invoke-RestMethod call: $Method $Uri" }
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid'; displayName = 'Op'; roles = @('Bower.Operator') } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        Connect-BowerManagement -Endpoint https://bower-api.example.test -AccessToken (New-TestSecureString 'remote-token') | Out-Null
    }
    AfterAll {
        Disconnect-BowerManagement
    }

    It 'posts the profile content to /api/privacy-profiles/validate' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { $script:ValidSummary | ConvertFrom-Json } -ParameterFilter { $Uri.AbsolutePath -eq '/api/privacy-profiles/validate' }
        $result = Test-BowerPrivacyProfile -Content "kind: PrivacyProfile`n" -Remote
        $result.Source | Should -Be 'Remote'
        $result.valid | Should -BeTrue
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/privacy-profiles/validate' -and
            ((Get-TestBodyText $Body) | ConvertFrom-Json).content -eq "kind: PrivacyProfile`n"
        }
        Should -Invoke -ModuleName Bower.Privacy Invoke-BowerCli -Times 0
    }

    It 'explains that Bower.Management is required' {
        Mock -ModuleName Bower.Privacy Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-BowerManagementRequest' }
        { Test-BowerPrivacyProfile -Content 'x' -Remote } | Should -Throw '*needs Bower.Management*Connect-BowerManagement*'
    }
}

Describe 'New-BowerCustomDetector' {
    It 'emits the customDetectors YAML from the spec example' {
        $yaml = New-BowerCustomDetector -Id custom.employee-id -Pattern 'EMP-\d{6}' -Action mask -WholeWord `
            -Match 'EMP-123456', 'user EMP-000001 logged in' -NoMatch 'EMP-12345' -Description 'Contoso employee numbers'

        $expected = @(
            'customDetectors:'
            '  - id: custom.employee-id'
            "    description: 'Contoso employee numbers'"
            "    pattern: 'EMP-\d{6}'"
            '    ignoreCase: false'
            '    wholeWord: true'
            '    action: mask'
            '    tests:'
            '      match:'
            "        - 'EMP-123456'"
            "        - 'user EMP-000001 logged in'"
            '      noMatch:'
            "        - 'EMP-12345'"
        ) -join "`n"
        $yaml | Should -BeExactly $expected
    }

    It 'combines piped detectors into one list' {
        $yaml = @(
            [pscustomobject]@{ Id = 'custom.ticket-ref'; Pattern = 'TKT-[0-9]{8}'; Action = 'sha256'; Match = @('TKT-12345678') }
            [pscustomobject]@{ Id = 'custom.badge'; Pattern = 'BDG[0-9]{5}'; Action = 'alert-only'; Match = @('BDG00042'); IgnoreCase = $true }
        ) | New-BowerCustomDetector -ListItemOnly

        $yaml | Should -Not -Match 'customDetectors:'
        ([regex]::Matches($yaml, '(?m)^  - id: ')).Count | Should -Be 2
        $yaml | Should -Match '(?m)^    ignoreCase: true$'
        $yaml | Should -Match '(?m)^      noMatch: \[\]$'
        $yaml | Should -Match '(?m)^    action: alert-only$'
    }

    It 'quotes single quotes and control characters safely' {
        $yaml = New-BowerCustomDetector -Id custom.quote -Pattern "O'Brien" -Action remove -Match "line1`nO'Brien"
        $yaml | Should -Match "(?m)^    pattern: 'O''Brien'$"
        $yaml | Should -Match '(?m)^        - "line1\\nO''Brien"$'
    }

    It 'validates the id format and length' -ForEach @(
        @{ Id = 'employee-id' }, @{ Id = 'custom.Employee' }, @{ Id = 'custom.employee--id' }, @{ Id = 'custom.-x' }, @{ Id = 'custom.' + ('a' * 58) }
    ) {
        { New-BowerCustomDetector -Id $Id -Pattern 'x' -Action mask -Match 'x' } | Should -Throw "*Custom detector id '$Id' must be custom.<name>*"
    }

    It 'accepts an id of exactly 64 characters' {
        { New-BowerCustomDetector -Id ('custom.' + ('a' * 57)) -Pattern 'x' -Action mask -Match 'x' } | Should -Not -Throw
    }

    It 'enforces sample counts, sample lengths and pattern length' {
        { New-BowerCustomDetector -Id custom.x -Pattern 'x' -Action mask -Match @() } | Should -Throw
        { New-BowerCustomDetector -Id custom.x -Pattern 'x' -Action mask -Match (1..17 | ForEach-Object { "s$_" }) } | Should -Throw
        { New-BowerCustomDetector -Id custom.x -Pattern 'x' -Action mask -Match ('x' * 1025) } | Should -Throw
        { New-BowerCustomDetector -Id custom.x -Pattern ('x' * 513) -Action mask -Match 'x' } | Should -Throw
        { New-BowerCustomDetector -Id custom.x -Pattern 'x' -Action mask -Match 'x' -Description ('d' * 257) } | Should -Throw
        { New-BowerCustomDetector -Id custom.x -Pattern 'x' -Action obliterate -Match 'x' } | Should -Throw
    }

    It 'rejects duplicate ids and more than 32 detectors' {
        { @(
                [pscustomobject]@{ Id = 'custom.a'; Pattern = 'a'; Action = 'mask'; Match = @('a') }
                [pscustomobject]@{ Id = 'custom.a'; Pattern = 'b'; Action = 'mask'; Match = @('b') }
            ) | New-BowerCustomDetector } | Should -Throw "*Custom detector id 'custom.a' is defined more than once.*"
        { 1..33 | ForEach-Object { [pscustomobject]@{ Id = "custom.d$_"; Pattern = 'a'; Action = 'mask'; Match = @('a') } } | New-BowerCustomDetector } |
            Should -Throw '*at most 32 custom detectors*'
    }
}

Describe 'ConvertTo-BowerSecretFieldName' {
    It 'normalises like the engine and flags duplicates' {
        $result = 'sessionKey', 'session-key', 'X_Contoso_Signature' | ConvertTo-BowerSecretFieldName
        $result.NormalizedName | Should -Be @('sessionkey', 'sessionkey', 'xcontososignature')
        $result.Duplicate | Should -Be @($false, $true, $false)
    }

    It 'keeps non-ASCII letters and digits' {
        (ConvertTo-BowerSecretFieldName -Name 'Clé-API_2').NormalizedName | Should -Be 'cléapi2'
    }

    It 'rejects names without letters or digits' {
        $output = ConvertTo-BowerSecretFieldName -Name '--', 'token' -ErrorAction Continue 2>&1
        ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Exception.Message | Should -Be "Secret field name '--' has no letters or digits."
        ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).NormalizedName | Should -Be 'token'
    }

    It 'emits a de-duplicated secretFieldNames snippet' {
        ConvertTo-BowerSecretFieldName -Name sessionKey, session-key, "x-contoso'sig" -AsYaml | Should -BeExactly "secretFieldNames: ['sessionKey', 'x-contoso''sig']"
    }

    It 'enforces the 64-name limit' {
        { 1..65 | ForEach-Object { "field$_" } | ConvertTo-BowerSecretFieldName -AsYaml } | Should -Throw '*at most 64 secretFieldNames*'
    }
}
