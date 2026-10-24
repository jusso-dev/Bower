BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BowerTestModule -Name Bower.Management
    # Fallback: any request no test mocked fails instead of reaching the network.
    Mock -ModuleName Bower.Management Invoke-RestMethod { throw "Unmocked Invoke-RestMethod call: $Method $Uri" }
    $script:PlainAccessToken = 'mgmt-access-token-SECRET-ABCDEF0123456789'
    $script:Endpoint = 'https://bower-api.example.test'
    $script:VersionId = '3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6'

    function Connect-TestManagement {
        Connect-BowerManagement -Endpoint $script:Endpoint -AccessToken (New-TestSecureString $script:PlainAccessToken) | Out-Null
    }

    function Get-TestJsonBody {
        param([AllowNull()][object] $Body)
        if ($null -eq $Body) { return $null }
        (Get-TestBodyText $Body) | ConvertFrom-Json -AsHashtable
    }
}

Describe 'Connect-BowerManagement' {
    BeforeEach {
        Disconnect-BowerManagement
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex Admin'; roles = @('Bower.Administrator', 'Bower.Viewer'); developmentAuthentication = $false }
        } -ParameterFilter { $Uri.AbsolutePath -like '*/api/access/me' }
    }

    It 'verifies the connection with GET /api/access/me using a SecureString bearer token' {
        $connection = Connect-BowerManagement -Endpoint $script:Endpoint -AccessToken (New-TestSecureString $script:PlainAccessToken)

        $connection.DisplayName | Should -Be 'Alex Admin'
        $connection.Roles | Should -Contain 'Bower.Administrator'
        $connection.AuthenticationMethod | Should -Be 'AccessToken'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'GET' -and $Uri.AbsoluteUri -eq 'https://bower-api.example.test/api/access/me' -and
            $Authentication -eq 'Bearer' -and $Token -is [securestring] -and
            (ConvertFrom-TestSecureString $Token) -eq $script:PlainAccessToken -and
            -not $PesterBoundParameters.ContainsKey('Headers') -and -not $PesterBoundParameters.ContainsKey('Body')
        }
    }

    It 'keeps an endpoint sub-path in front of /api' {
        Connect-BowerManagement -Endpoint https://proxy.example.test/bower/ -AccessToken (New-TestSecureString 't') | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -ParameterFilter { $Uri.AbsoluteUri -eq 'https://proxy.example.test/bower/api/access/me' }
    }

    It 'never exposes the token in the connection object' {
        $connection = Connect-BowerManagement -Endpoint $script:Endpoint -AccessToken (New-TestSecureString $script:PlainAccessToken)
        @($connection.PSObject.Properties.Name) | Should -Not -Contain 'Token'
        ($connection | ConvertTo-Json -Depth 5) | Should -Not -Match ([regex]::Escape($script:PlainAccessToken))
        (Get-BowerManagementConnection | Out-String) | Should -Not -Match ([regex]::Escape($script:PlainAccessToken))
    }

    It 'never writes the token to verbose or debug output' {
        $streams = & {
            Connect-BowerManagement -Endpoint $script:Endpoint -AccessToken (New-TestSecureString $script:PlainAccessToken) -Verbose -Debug
            Get-BowerManagementConnection -Verbose -Debug
        } *>&1 | Out-String
        $streams | Should -Match 'GET https://bower-api.example.test/api/access/me'
        $streams | Should -Not -Match ([regex]::Escape($script:PlainAccessToken))
    }

    It 'acquires the token through Az.Accounts for the audience' {
        Mock -ModuleName Bower.Management Get-BowerAzAccessToken {
            [pscustomobject]@{ Token = (New-TestSecureString 'az-token'); ExpiresOn = [datetimeoffset]::UtcNow.AddHours(1) }
        }
        $connection = Connect-BowerManagement -Endpoint $script:Endpoint -Audience api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee -TenantId 11111111-2222-3333-4444-555555555555
        $connection.AuthenticationMethod | Should -Be 'AzAccounts'
        Should -Invoke -ModuleName Bower.Management Get-BowerAzAccessToken -Times 1 -Exactly -ParameterFilter {
            $ResourceUrl -eq 'api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -and $TenantId -eq '11111111-2222-3333-4444-555555555555'
        }
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -ParameterFilter { (ConvertFrom-TestSecureString $Token) -eq 'az-token' }
    }

    It 'refreshes an expiring Az.Accounts token before the next request' {
        $script:azCalls = 0
        Mock -ModuleName Bower.Management Get-BowerAzAccessToken {
            $script:azCalls++
            [pscustomobject]@{ Token = (New-TestSecureString "az-token-$script:azCalls"); ExpiresOn = [datetimeoffset]::UtcNow.AddSeconds(30) }
        }
        Mock -ModuleName Bower.Management Invoke-RestMethod { @() } -ParameterFilter { $Uri.AbsolutePath -eq '/api/jobs' }
        Connect-BowerManagement -Endpoint $script:Endpoint -Audience api://bower | Out-Null
        Get-BowerJob
        # Each token expires within two minutes, so every request acquires a fresh one.
        Should -Invoke -ModuleName Bower.Management Get-BowerAzAccessToken -Times 3 -Exactly
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -ParameterFilter { $Uri.AbsolutePath -eq '/api/jobs' -and (ConvertFrom-TestSecureString $Token) -eq 'az-token-3' }
    }

    It 'uses a token provider script block' {
        Connect-BowerManagement -Endpoint $script:Endpoint -TokenProvider { New-TestSecureString 'provider-token' } | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -ParameterFilter { (ConvertFrom-TestSecureString $Token) -eq 'provider-token' }
    }

    It 'refuses plain http to a remote endpoint' {
        { Connect-BowerManagement -Endpoint http://bower-api.example.test -AccessToken (New-TestSecureString 't') } | Should -Throw '*must use https*'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0
    }

    It 'allows loopback http for a local management API' {
        Connect-BowerManagement -Endpoint http://127.0.0.1:4320 -AccessToken (New-TestSecureString 't') | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -ParameterFilter { $AllowUnencryptedAuthentication -eq $true }
    }

    It 'does not keep a connection when verification fails' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 401) } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        { Connect-BowerManagement -Endpoint $script:Endpoint -AccessToken (New-TestSecureString 't') } | Should -Throw '*HTTP 401 (Unauthorized)*Run Connect-BowerManagement again*'
        Get-BowerManagementConnection | Should -BeNullOrEmpty
    }

    It 'does not write tokens or connection state to disk' {
        $source = Get-ChildItem -Path (Join-Path $script:ModulesRoot 'Bower.Management') -Filter *.ps1 -Recurse | Get-Content -Raw
        ($source -join "`n") | Should -Not -Match '(?i)\b(Set-Content|Add-Content|Out-File|Export-Clixml|Export-Csv|WriteAllText|WriteAllBytes)\b'
    }
}

Describe 'Management cmdlets before connecting' {
    It 'fail with a clear message' {
        Disconnect-BowerManagement
        { Get-BowerCollector } | Should -Throw '*Not connected to Bower management. Run Connect-BowerManagement first.*'
    }
}

Describe 'Collector cmdlets' {
    BeforeAll {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex'; roles = @() } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        Connect-TestManagement
    }
    BeforeEach {
        Mock -ModuleName Bower.Management Wait-BowerRetryDelay { }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            [pscustomobject]@{ id = 'approval-1'; collectorId = 'web-07'; action = 'x'; reason = 'r' }
        } -ParameterFilter { $Method -eq 'POST' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            @([pscustomobject]@{ id = 'web-07'; status = 'Pending' }, [pscustomobject]@{ id = 'web 08'; status = 'Pending' })
        } -ParameterFilter { $Method -eq 'GET' -and $Uri.AbsolutePath -eq '/api/collectors' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            [pscustomobject]@{ id = 'web-07'; status = 'Active' }
        } -ParameterFilter { $Method -eq 'GET' -and $Uri.AbsolutePath -like '/api/collectors/*' }
    }

    It 'lists collectors filtered by status' {
        $collectors = Get-BowerCollector -Status Pending
        $collectors.Count | Should -Be 2
        $collectors[0].PSObject.TypeNames[0] | Should -Be 'Bower.Collector'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.PathAndQuery -eq '/api/collectors?status=Pending' }
    }

    It 'gets one collector by escaped ID' {
        Get-BowerCollector -Id 'web 08' | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.AbsoluteUri -eq 'https://bower-api.example.test/api/collectors/web%2008' }
    }

    It 'retries GET requests on 503' {
        $script:getAttempts = 0
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            $script:getAttempts++
            if ($script:getAttempts -eq 1) { throw (New-HttpErrorRecord -StatusCode 503 -RetryAfterSeconds 2) }
            @()
        } -ParameterFilter { $Uri.AbsolutePath -eq '/api/audit' }
        Get-BowerAuditEvent | Out-Null
        Should -Invoke -ModuleName Bower.Management Wait-BowerRetryDelay -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'does not retry POST requests on 503' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 503) } -ParameterFilter { $Method -eq 'POST' }
        { Suspend-BowerCollector -Id web-07 -Reason 'INC-1' -Confirm:$false -ErrorAction Stop } | Should -Throw '*HTTP 503*'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' }
        Should -Invoke -ModuleName Bower.Management Wait-BowerRetryDelay -Times 0
    }

    It 'retries POST requests on 429' {
        $script:postAttempts = 0
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            $script:postAttempts++
            if ($script:postAttempts -eq 1) { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterSeconds 1) }
            [pscustomobject]@{ id = 'approval-1' }
        } -ParameterFilter { $Method -eq 'POST' }
        Approve-BowerCollector -Id web-07 -Reason 'ok' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 2 -Exactly -ParameterFilter { $Method -eq 'POST' }
    }

    It 'POSTs <Command> to <Path> with the reason' -ForEach @(
        @{ Command = 'Approve-BowerCollector'; Path = '/api/approvals/web-07/approve' }
        @{ Command = 'Deny-BowerCollector'; Path = '/api/approvals/web-07/reject' }
        @{ Command = 'Suspend-BowerCollector'; Path = '/api/collectors/web-07/suspend' }
        @{ Command = 'Revoke-BowerCollector'; Path = '/api/collectors/web-07/revoke' }
        @{ Command = 'Resume-BowerCollector'; Path = '/api/collectors/web-07/reinstate' }
    ) {
        $record = & $Command -Id web-07 -Reason 'Change CHG-1' -Confirm:$false
        $record.PSObject.TypeNames[0] | Should -Be 'Bower.ApprovalRecord'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq $Path -and
            (Get-TestJsonBody $Body).reason -eq 'Change CHG-1' -and (Get-TestJsonBody $Body).Count -eq 1
        }
    }

    It '<Command> does nothing with -WhatIf' -ForEach @(
        @{ Command = 'Approve-BowerCollector' }, @{ Command = 'Deny-BowerCollector' }, @{ Command = 'Suspend-BowerCollector' },
        @{ Command = 'Revoke-BowerCollector' }, @{ Command = 'Resume-BowerCollector' }
    ) {
        & $Command -Id web-07 -Reason 'r' -WhatIf
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'requires a non-blank reason of at most 500 characters' {
        { Revoke-BowerCollector -Id web-07 -Reason '   ' -Confirm:$false -ErrorAction Stop } | Should -Throw '*Reason must be 1-500 characters*'
        { Revoke-BowerCollector -Id web-07 -Reason ('x' * 501) -Confirm:$false -ErrorAction Stop } | Should -Throw '*Reason must be 1-500 characters*'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'accepts pipeline input from Get-BowerCollector' {
        Get-BowerCollector -Status Pending | Approve-BowerCollector -Reason 'Inventory verified' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.AbsolutePath -eq '/api/approvals/web-07/approve' }
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.AbsoluteUri -eq 'https://bower-api.example.test/api/approvals/web%2008/approve' }
    }

    It 'propagates the API error message as a non-terminating error' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 409 -Body '{"error":"Collector is not in a state that allows this decision."}')
        } -ParameterFilter { $Method -eq 'POST' }
        $output = Approve-BowerCollector -Id web-07 -Reason 'ok' -Confirm:$false -ErrorAction Continue 2>&1
        $output | Should -HaveCount 1
        $output[0] | Should -BeOfType [System.Management.Automation.ErrorRecord]
        $output[0].Exception.Message | Should -Be 'Bower management API POST /api/approvals/web-07/approve failed: HTTP 409 (Conflict): Collector is not in a state that allows this decision.'
        $output[0].CategoryInfo.Category | Should -Be 'ResourceExists'
        $output[0].FullyQualifiedErrorId | Should -BeLike 'BowerManagementApi409*'
    }

    It 'flattens validation problem errors' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 400 -Body '{"title":"One or more validation errors occurred.","errors":{"reason":["A reason of 1-500 characters is required."]}}')
        } -ParameterFilter { $Method -eq 'POST' }
        { Revoke-BowerCollector -Id web-07 -Reason 'x' -Confirm:$false -ErrorAction Stop } | Should -Throw '*HTTP 400 (BadRequest): reason: A reason of 1-500 characters is required.'
    }

    It 'explains 403 responses in terms of Bower app roles' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 403) } -ParameterFilter { $Method -eq 'POST' }
        { Revoke-BowerCollector -Id web-07 -Reason 'x' -Confirm:$false -ErrorAction Stop } | Should -Throw '*HTTP 403 (Forbidden). Your Bower app role does not allow this operation.'
    }
}

Describe 'Audit and job cmdlets' {
    BeforeAll {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex'; roles = @() } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        Connect-TestManagement
    }
    BeforeEach {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            @(
                [pscustomobject]@{ id = '1'; action = 'collector.revoked'; targetType = 'collector'; targetId = 'web-07' }
                [pscustomobject]@{ id = '2'; action = 'privacy-profile.approved'; targetType = 'privacy-profile-version'; targetId = $script:VersionId }
            )
        } -ParameterFilter { $Uri.AbsolutePath -eq '/api/audit' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            @([pscustomobject]@{ id = 'collector-staleness' }, [pscustomobject]@{ id = 'collector-inactivity' })
        } -ParameterFilter { $Uri.AbsolutePath -eq '/api/jobs' }
        Mock -ModuleName Bower.Management Invoke-RestMethod { $null } -ParameterFilter { $Uri.AbsolutePath -like '/api/jobs/*/trigger' }
    }

    It 'filters audit events by action wildcard' {
        $events = @(Get-BowerAuditEvent -Action 'privacy-profile.*')
        $events.Count | Should -Be 1
        $events[0].targetType | Should -Be 'privacy-profile-version'
    }

    It 'filters audit events by target' {
        @(Get-BowerAuditEvent -TargetType collector -TargetId web-07).Count | Should -Be 1
    }

    It 'lists and filters jobs' {
        @(Get-BowerJob).Count | Should -Be 2
        (Get-BowerJob -Id '*staleness').id | Should -Be 'collector-staleness'
    }

    It 'triggers a job with POST /api/jobs/{id}/trigger' {
        Start-BowerJob -Id collector-staleness -Confirm:$false
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/jobs/collector-staleness/trigger'
        }
    }

    It 'does not trigger jobs with -WhatIf' {
        Get-BowerJob | Start-BowerJob -WhatIf
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }
}

Describe 'Privacy profile cmdlets' {
    BeforeAll {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex'; roles = @() } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        Connect-TestManagement
        $script:ProfileYaml = "apiVersion: bower.security/v1`nkind: PrivacyProfile`nmetadata:`n  id: contoso-app`n  version: 1.2.0`n"
    }
    BeforeEach {
        Set-Content -LiteralPath (Join-Path $TestDrive 'profile.yaml') -Value $script:ProfileYaml -NoNewline
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ id = $script:VersionId; status = 'PendingReview' } } -ParameterFilter { $Method -eq 'POST' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            @(
                [pscustomobject]@{ id = $script:VersionId; profileId = 'contoso-app'; version = '1.2.0'; status = 'PendingReview' }
                [pscustomobject]@{ id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; profileId = 'contoso-app'; version = '1.1.0'; status = 'Approved' }
                [pscustomobject]@{ id = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; profileId = 'other'; version = '0.1.0'; status = 'Approved' }
            )
        } -ParameterFilter { $Method -eq 'GET' -and $Uri.AbsolutePath -eq '/api/privacy-profiles' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            [pscustomobject]@{ id = $script:VersionId; content = 'yaml'; previousApprovedVersionId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
        } -ParameterFilter { $Method -eq 'GET' -and $Uri.AbsolutePath -like '/api/privacy-profiles/versions/*' }
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            @(
                [pscustomobject]@{ id = 2; collectorId = 'web-07'; versionId = $script:VersionId; action = 'assigned' }
                [pscustomobject]@{ id = 1; collectorId = 'web-08'; versionId = $null; action = 'cleared' }
            )
        } -ParameterFilter { $Method -eq 'GET' -and $Uri.AbsolutePath -eq '/api/privacy-profiles/assignments' }
    }

    It 'previews a profile against a sample with POST /api/privacy-profiles/preview' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            [pscustomobject]@{ valid = $true; errors = @(); redacted = '{}'; findings = @([pscustomobject]@{ detectorId = 'custom.employee-id'; action = 'mask'; path = '$.attributes.note' }) }
        } -ParameterFilter { $Uri.AbsolutePath -eq '/api/privacy-profiles/preview' }
        $preview = Invoke-BowerPrivacyProfilePreview -Path (Join-Path $TestDrive 'profile.yaml') -Sample @{ attributes = @{ note = 'EMP-123456' } }
        $preview.findings[0].detectorId | Should -Be 'custom.employee-id'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $body = Get-TestJsonBody $Body
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/privacy-profiles/preview' -and
            $body.content -eq $script:ProfileYaml -and ($body.sample | ConvertFrom-Json).attributes.note -eq 'EMP-123456' -and $body.Count -eq 2
        }
    }

    It 'rejects preview samples that are not JSON or exceed 64 KiB' {
        { Invoke-BowerPrivacyProfilePreview -Content $script:ProfileYaml -Sample 'not json' } | Should -Throw '*Sample must be valid JSON*'
        { Invoke-BowerPrivacyProfilePreview -Content $script:ProfileYaml -Sample (@{ a = 'x' * 65536 } | ConvertTo-Json) } | Should -Throw '*at most 64 KiB*'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'submits a profile version with content and change summary' {
        $version = Submit-BowerPrivacyProfile -Path (Join-Path $TestDrive 'profile.yaml') -ChangeSummary 'Add employee detector' -Confirm:$false
        $version.PSObject.TypeNames[0] | Should -Be 'Bower.PrivacyProfileVersion'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $body = Get-TestJsonBody $Body
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/privacy-profiles' -and
            $body.content -eq $script:ProfileYaml -and $body.changeSummary -eq 'Add employee detector' -and $body.Count -eq 2
        }
    }

    It 'surfaces submission validation errors from the API' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 400 -Body '{"error":"Privacy profile version must be greater than 1.2.0."}')
        } -ParameterFilter { $Method -eq 'POST' }
        { Submit-BowerPrivacyProfile -Content $script:ProfileYaml -ChangeSummary 'x' -Confirm:$false } | Should -Throw '*HTTP 400 (BadRequest): Privacy profile version must be greater than 1.2.0.'
    }

    It 'does not submit with -WhatIf and requires a change summary' {
        Submit-BowerPrivacyProfile -Content $script:ProfileYaml -ChangeSummary 'x' -WhatIf
        { Submit-BowerPrivacyProfile -Content $script:ProfileYaml -ChangeSummary ('x' * 501) -Confirm:$false } | Should -Throw '*ChangeSummary must be 1-500 characters*'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'lists versions filtered by profile and status' {
        @(Get-BowerPrivacyProfileVersion -ProfileId contoso-app).Count | Should -Be 2
        (Get-BowerPrivacyProfileVersion -ProfileId contoso-app -Status Approved).version | Should -Be '1.1.0'
    }

    It 'gets a version detail by ID' {
        (Get-BowerPrivacyProfileVersion -Id $script:VersionId).previousApprovedVersionId | Should -Be 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.AbsolutePath -eq "/api/privacy-profiles/versions/$script:VersionId" }
    }

    It 'rejects malformed version IDs before calling the API' {
        { Get-BowerPrivacyProfileVersion -Id '../collectors' } | Should -Throw
        { Approve-BowerPrivacyProfileVersion -Id 'ABC' -Reason 'r' -Confirm:$false } | Should -Throw
    }

    It '<Command> POSTs to versions/{id}/<Action>' -ForEach @(
        @{ Command = 'Approve-BowerPrivacyProfileVersion'; Action = 'approve' }
        @{ Command = 'Deny-BowerPrivacyProfileVersion'; Action = 'reject' }
    ) {
        & $Command -Id $script:VersionId -Reason 'Reviewed with privacy office' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq "/api/privacy-profiles/versions/$script:VersionId/$Action" -and
            (Get-TestJsonBody $Body).reason -eq 'Reviewed with privacy office'
        }
    }

    It 'surfaces the two-person rule error' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 409 -Body '{"error":"The author of a privacy profile version cannot review it."}')
        } -ParameterFilter { $Method -eq 'POST' }
        { Approve-BowerPrivacyProfileVersion -Id $script:VersionId -Reason 'self review' -Confirm:$false -ErrorAction Stop } |
            Should -Throw '*HTTP 409 (Conflict): The author of a privacy profile version cannot review it.'
    }

    It 'pipes pending versions into approval' {
        Get-BowerPrivacyProfileVersion -Status PendingReview | Approve-BowerPrivacyProfileVersion -Reason 'ok' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri.AbsolutePath -eq "/api/privacy-profiles/versions/$script:VersionId/approve" }
    }

    It 'assigns an approved version to a collector' {
        Set-BowerCollectorPrivacyProfile -CollectorId web-07 -VersionId $script:VersionId -Reason 'Roll out PRIV-77' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $body = Get-TestJsonBody $Body
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/collectors/web-07/privacy-profile' -and
            $body.versionId -eq $script:VersionId -and $body.reason -eq 'Roll out PRIV-77' -and $body.Count -eq 2
        }
    }

    It 'clears a collector assignment' {
        Clear-BowerCollectorPrivacyProfile -CollectorId web-07 -Reason 'Rollback' -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $body = Get-TestJsonBody $Body
            $Method -eq 'POST' -and $Uri.AbsolutePath -eq '/api/collectors/web-07/privacy-profile/clear' -and $body.reason -eq 'Rollback' -and $body.Count -eq 1
        }
    }

    It '<Command> does nothing with -WhatIf' -ForEach @(
        @{ Command = 'Set-BowerCollectorPrivacyProfile'; Extra = @{ VersionId = '3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6' } }
        @{ Command = 'Clear-BowerCollectorPrivacyProfile'; Extra = @{} }
    ) {
        & $Command -CollectorId web-07 -Reason 'r' -WhatIf @Extra
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'surfaces assignment conflicts' {
        Mock -ModuleName Bower.Management Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 409 -Body '{"error":"Only approved privacy profile versions can be assigned."}')
        } -ParameterFilter { $Method -eq 'POST' }
        { Set-BowerCollectorPrivacyProfile -CollectorId web-07 -VersionId $script:VersionId -Reason 'r' -Confirm:$false -ErrorAction Stop } |
            Should -Throw '*Only approved privacy profile versions can be assigned.'
    }

    It 'lists assignment history filtered by collector' {
        $rows = @(Get-BowerPrivacyProfileAssignment -CollectorId web-07)
        $rows.Count | Should -Be 1
        $rows[0].action | Should -Be 'assigned'
        @(Get-BowerPrivacyProfileAssignment -VersionId $script:VersionId).Count | Should -Be 1
    }
}

Describe 'Invoke-BowerManagementRequest' {
    BeforeAll {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex'; roles = @() } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/access/me' }
        Connect-TestManagement
    }

    It 'sends JSON bodies to paths under /api' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ valid = $true } } -ParameterFilter { $Uri.AbsolutePath -eq '/api/privacy-profiles/validate' }
        (Invoke-BowerManagementRequest -Method POST -Path /privacy-profiles/validate -Body @{ content = 'x' }).valid | Should -BeTrue
        Should -Invoke -ModuleName Bower.Management Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and (Get-TestJsonBody $Body).content -eq 'x' -and $ContentType -eq 'application/json; charset=utf-8'
        }
    }

    It 'rejects absolute URLs, query strings and dot segments' {
        { Invoke-BowerManagementRequest -Path 'https://evil.example/x' } | Should -Throw
        { Invoke-BowerManagementRequest -Path '/collectors?status=Pending' } | Should -Throw
        { Invoke-BowerManagementRequest -Path '/collectors/../audit' } | Should -Throw '*dot segments*'
    }
}

Describe 'Disconnect-BowerManagement' {
    It 'clears the in-memory connection' {
        Mock -ModuleName Bower.Management Invoke-RestMethod { [pscustomobject]@{ objectId = 'oid-1'; displayName = 'Alex'; roles = @() } }
        Connect-TestManagement
        Disconnect-BowerManagement
        Get-BowerManagementConnection | Should -BeNullOrEmpty
        InModuleScope Bower.Management { $script:BowerManagementConnection } | Should -BeNullOrEmpty
    }
}
