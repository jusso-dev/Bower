BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BowerTestModule -Name Bower.Policy

    # The bower CLI is always mocked here; its real output shape is owned by the CLI
    # (src/Bower.Cli and rust/crates/bower-cli, kept in parity by their own tests).
    Mock -ModuleName Bower.Policy Resolve-BowerCliPath { if ($Path) { $Path } else { "/mock/bin/$Name" } }
    Mock -ModuleName Bower.Policy Invoke-BowerCli { throw "Unmocked bower call: $($ArgumentList -join ' ')" }

    $script:PolicyDirectory = Join-Path $TestDrive 'policies'
    New-Item -ItemType Directory -Path $script:PolicyDirectory | Out-Null
    $script:Accepted = Join-Path $TestDrive 'accepted.json'
    $script:Noise = Join-Path $TestDrive 'noise.json'
    Set-Content -LiteralPath $script:Accepted -Value '{}'
    Set-Content -LiteralPath $script:Noise -Value '{}'
    $script:TestOutput = @{
        bundleHash  = 'sha256:' + ('b' * 64)
        policyCount = 5
        results     = @(
            @{
                file = $script:Accepted; eventId = 'evt-1'; decision = 'redactandaccept'; wouldQueue = $true; privacyAlert = $true
                reasons = @('Approved semantic event type: authentication_failure')
                policy = @{ policyId = 'BWR-POL-AUTH-FAILURE'; policyVersion = '1.0.0'; policyHash = 'sha256:' + ('c' * 64); score = 98 }
            },
            @{
                file = $script:Noise; eventId = 'evt-2'; decision = 'reject'; wouldQueue = $false; privacyAlert = $false
                reasons = @('No approved policy matched event category and type')
                policy = @{ policyId = 'BWR-POL-DEFAULT-DENY'; policyVersion = '1.0.0'; policyHash = 'builtin:default-deny-v1'; score = 0 }
            }
        )
    } | ConvertTo-Json -Depth 6
}

Describe 'Test-BowerPolicy' {
    It 'runs bower validate on the resolved directory and returns each policy hash' {
        Mock -ModuleName Bower.Policy Invoke-BowerCli {
            [pscustomobject]@{
                ExitCode = 0
                StdOut   = '{"valid":true,"policyCount":1,"policies":[{"Id":"BWR-POL-AUTH-FAILURE","Version":"1.0.0","Hash":"sha256:abc"}]}'
                StdErr   = ''
            }
        }
        $result = Test-BowerPolicy -PolicyDirectory $script:PolicyDirectory
        $result.PSObject.TypeNames[0] | Should -Be 'Bower.PolicyValidation'
        $result.Valid | Should -BeTrue
        $result.PolicyCount | Should -Be 1
        $result.Policies[0].Id | Should -Be 'BWR-POL-AUTH-FAILURE'
        $result.Policies[0].Hash | Should -Be 'sha256:abc'
        $result.Error | Should -BeNullOrEmpty
        Should -Invoke -ModuleName Bower.Policy Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq '/mock/bin/bower' -and $ArgumentList.Count -eq 3 -and $ArgumentList[0] -eq 'validate' -and
            $ArgumentList[1] -eq '--policy-directory' -and $ArgumentList[2] -eq (Resolve-Path $script:PolicyDirectory).ProviderPath
        }
    }

    It 'returns an invalid result with the bounded loader message when a policy does not load' {
        Mock -ModuleName Bower.Policy Invoke-BowerCli {
            [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'Unsupported policy action: allow' + ('x' * 2000) }
        }
        $result = Test-BowerPolicy -PolicyDirectory $script:PolicyDirectory
        $result.Valid | Should -BeFalse
        $result.PolicyCount | Should -Be 0
        $result.Error | Should -BeLike 'Unsupported policy action: allow*...'
        $result.Error.Length | Should -BeLessOrEqual 1003
    }

    It 'fails when the directory is missing, before running the CLI' {
        { Test-BowerPolicy -PolicyDirectory (Join-Path $TestDrive 'missing') } | Should -Throw "*Policy directory*was not found*"
        Should -Invoke -ModuleName Bower.Policy Invoke-BowerCli -Times 0
    }

    It 'fails when a successful run prints no JSON' {
        Mock -ModuleName Bower.Policy Invoke-BowerCli { [pscustomobject]@{ ExitCode = 0; StdOut = 'bower 0.1.0'; StdErr = '' } }
        { Test-BowerPolicy -PolicyDirectory $script:PolicyDirectory } | Should -Throw '*did not return a JSON document*'
    }
}

Describe 'Test-BowerPolicyEvent' {
    BeforeEach {
        Mock -ModuleName Bower.Policy Invoke-BowerCli { [pscustomobject]@{ ExitCode = 0; StdOut = $script:TestOutput; StdErr = '' } }
    }

    It 'runs bower policy test once for all piped files with the bundle options' {
        $pack = Join-Path $TestDrive 'aws.bowerpack'; Set-Content -LiteralPath $pack -Value 'x'
        $key = Join-Path $TestDrive 'pack.pub'; Set-Content -LiteralPath $key -Value 'x'
        $results = @(Get-ChildItem -LiteralPath $script:Accepted, $script:Noise |
                Test-BowerPolicyEvent -PolicyDirectory $script:PolicyDirectory -PackPath $pack -TrustedKeyPath $key)

        $results.Count | Should -Be 2
        $results[0].PSObject.TypeNames[0] | Should -Be 'Bower.PolicyEventResult'
        $results[0].Decision | Should -Be 'redactandaccept'
        $results[0].WouldQueue | Should -BeTrue
        $results[0].PrivacyAlert | Should -BeTrue
        $results[0].PolicyId | Should -Be 'BWR-POL-AUTH-FAILURE'
        $results[0].Score | Should -Be 98
        $results[1].Decision | Should -Be 'reject'
        $results[1].MatchesExpectation | Should -BeNullOrEmpty
        $results[1].BundleHash | Should -Be ('sha256:' + ('b' * 64))
        Should -Invoke -ModuleName Bower.Policy Invoke-BowerCli -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq 'policy' -and $ArgumentList[1] -eq 'test' -and
            $ArgumentList[2] -eq (Resolve-Path $script:Accepted).ProviderPath -and $ArgumentList[3] -eq (Resolve-Path $script:Noise).ProviderPath -and
            (Test-ArgumentSequence $ArgumentList @('--policy-directory', (Resolve-Path $script:PolicyDirectory).ProviderPath)) -and
            (Test-ArgumentSequence $ArgumentList @('--pack', (Resolve-Path $pack).ProviderPath)) -and
            (Test-ArgumentSequence $ArgumentList @('--trusted-key', (Resolve-Path $key).ProviderPath)) -and
            $ArgumentList -notcontains '--expect'
        }
    }

    It 'writes a non-terminating error for each decision that differs from -ExpectedDecision' {
        $results = @(Test-BowerPolicyEvent -Path $script:Accepted, $script:Noise -PolicyDirectory $script:PolicyDirectory `
                -ExpectedDecision redact-and-accept -ErrorVariable mismatches -ErrorAction SilentlyContinue)
        $results.Count | Should -Be 2
        $results[0].MatchesExpectation | Should -BeTrue
        $results[1].MatchesExpectation | Should -BeFalse
        $mismatches.Count | Should -Be 1
        $mismatches[0].FullyQualifiedErrorId | Should -BeLike 'BowerPolicyDecisionMismatch*'
        $mismatches[0].Exception.Message | Should -BeLike "*noise.json' was 'reject', expected 'redactandaccept'*"
        { Test-BowerPolicyEvent -Path $script:Noise -PolicyDirectory $script:PolicyDirectory -ExpectedDecision accept -ErrorAction Stop } |
            Should -Throw '*expected ''accept''*'
    }

    It 'fails for a missing event file before running the CLI' {
        { Test-BowerPolicyEvent -Path (Join-Path $TestDrive 'missing.json') -PolicyDirectory $script:PolicyDirectory } |
            Should -Throw "*Event file*was not found*"
        Should -Invoke -ModuleName Bower.Policy Invoke-BowerCli -Times 0
    }

    It 'surfaces bounded stderr when the bundle does not load' {
        Mock -ModuleName Bower.Policy Invoke-BowerCli { [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'Policy directory does not exist: x' } }
        { Test-BowerPolicyEvent -Path $script:Accepted -PolicyDirectory $script:PolicyDirectory } |
            Should -Throw '*bower policy test failed (exit code 1): Policy directory does not exist: x*'
    }

    It 'rejects unknown expected decisions' {
        { Test-BowerPolicyEvent -Path $script:Accepted -ExpectedDecision allow } | Should -Throw
    }
}

Describe 'New-BowerPolicy' {
    BeforeAll {
        $script:PolicyParameters = @{
            Id            = 'BWR-POL-ORDERS-EXPORT'
            Name          = "Order exports: it's quoted"
            Version       = '1.0.0'
            Owner         = 'Security Operations'
            EventCategory = 'data-access'
            EventType     = 'sensitive_data_exported'
            RequiredField = @('timeGenerated', 'actor.userId')
        }
    }

    It 'returns quoted YAML with every section' {
        $yaml = New-BowerPolicy @script:PolicyParameters -RecommendedField request.correlationId -ReviewDate ([datetime]'2027-06-30') `
            -NeverSample -MinimumValueScore 80 -RoutingDestination security-events
        $yaml | Should -BeLike "apiVersion: bower.security/v1`nkind: TelemetryPolicy*"
        $yaml | Should -Match "(?m)^  name: 'Order exports: it''s quoted'$"
        $yaml | Should -Match "(?m)^  version: '1\.0\.0'$"
        $yaml | Should -Match "(?m)^  reviewDate: 2027-06-30$"
        $yaml | Should -Match "(?m)^  eventCategories:\n    - 'data-access'$"
        $yaml | Should -Match "(?m)^  requiredFields:\n    - 'timeGenerated'\n    - 'actor\.userId'$"
        $yaml | Should -Match "(?m)^  atLeastOne: \[\]$"
        $yaml | Should -Match "(?m)^  action: accept\n  minimumValueScore: 80\n  neverSample: true$"
        $yaml | Should -Match "(?m)^routing:\n  destination: 'security-events'$"
        $yaml | Should -Not -Match 'profile:'
    }

    It 'quotes values so they cannot change the YAML structure' {
        $yaml = New-BowerPolicy @script:PolicyParameters -Owner "ops`nkind: Evil"
        $yaml | Should -Match '(?m)^  owner: "ops\\nkind: Evil"$'
        ($yaml -split "`n" | Where-Object { $_ -like 'kind:*' }).Count | Should -Be 1
    }

    It 'requires a category or type and validates names' {
        $parameters = $script:PolicyParameters.Clone(); $parameters.Remove('EventCategory'); $parameters.Remove('EventType')
        { New-BowerPolicy @parameters } | Should -Throw '*must match something*'
        { New-BowerPolicy @script:PolicyParameters -Version 1.0 } | Should -Throw
        { New-BowerPolicy @script:PolicyParameters -Action allow } | Should -Throw
        { New-BowerPolicy @script:PolicyParameters -RequiredField 'actor.userId; rm' } | Should -Throw
        { New-BowerPolicy @script:PolicyParameters -MinimumValueScore 101 } | Should -Throw
    }

    It 'writes the file after confirmation and keeps an existing file without -Force' {
        $path = Join-Path $TestDrive 'orders.yaml'
        $file = New-BowerPolicy @script:PolicyParameters -Path $path -Confirm:$false
        $file.FullName | Should -Be $path
        [System.IO.File]::ReadAllText($path) | Should -BeLike 'apiVersion: bower.security/v1*'
        [System.IO.File]::ReadAllBytes($path)[0] | Should -Not -Be 0xEF
        { New-BowerPolicy @script:PolicyParameters -Path $path -Confirm:$false } | Should -Throw '*already exists*'
        New-BowerPolicy @script:PolicyParameters -Name 'Replaced' -Path $path -Force -Confirm:$false | Out-Null
        [System.IO.File]::ReadAllText($path) | Should -Match "name: 'Replaced'"
    }

    It 'writes nothing with -WhatIf' {
        $path = Join-Path $TestDrive 'whatif.yaml'
        New-BowerPolicy @script:PolicyParameters -Path $path -WhatIf | Should -BeNullOrEmpty
        Test-Path -LiteralPath $path | Should -BeFalse
    }
}
