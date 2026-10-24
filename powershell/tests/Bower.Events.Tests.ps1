BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BowerTestModule -Name Bower.Events
    # Fallback: any request no test mocked fails instead of reaching the network.
    Mock -ModuleName Bower.Events Invoke-RestMethod { throw "Unmocked Invoke-RestMethod call: $Method $Uri" }
    $script:PlainToken = 'producer-token-SECRET-0123456789abcdef0123456789'
    $script:ProducerToken = New-TestSecureString -Value $script:PlainToken
}

Describe 'New-BowerSecurityEvent' {
    It 'builds a schema 1.0.0 envelope with required fields' {
        $event = New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction sign-in `
            -EventResult Failure -ApplicationName payroll -ApplicationEnvironment production -EventId 'e-1' `
            -TimeGenerated ([datetimeoffset]'2026-10-24T10:00:00+10:00') -Actor @{ userId = 'u-1'; type = 'human' } -EventSeverity Medium

        $event.PSObject.TypeNames[0] | Should -Be 'Bower.SecurityEvent'
        $event.schemaVersion | Should -Be '1.0.0'
        $event.eventId | Should -Be 'e-1'
        $event.timeGenerated | Should -Be '2026-10-24T00:00:00.0000000+00:00'
        $event.eventResult | Should -BeExactly 'failure'
        $event.eventSeverity | Should -BeExactly 'medium'
        $event.application.name | Should -Be 'payroll'
        $event.actor.userId | Should -Be 'u-1'
        @($event.PSObject.Properties.Name) | Should -Not -Contain 'target'
    }

    It 'generates a GUID event ID by default' {
        $event = New-BowerSecurityEvent -EventCategory data-access -EventType record_read -EventAction read -EventResult success -ApplicationName a -ApplicationEnvironment e
        { [guid]::Parse($event.eventId) } | Should -Not -Throw
    }

    It 'rejects an event type that breaks the schema pattern' {
        { New-BowerSecurityEvent -EventCategory authentication -EventType User_Sign_In -EventAction a -EventResult success -ApplicationName a -ApplicationEnvironment e } |
            Should -Throw '*EventType must match*'
    }

    It 'rejects unknown nested properties' {
        { New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction a -EventResult success -ApplicationName a -ApplicationEnvironment e -Actor @{ password = 'x' } } |
            Should -Throw "*actor property 'password' is not allowed*"
    }

    It 'rejects an actor type outside the enumeration' {
        { New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction a -EventResult success -ApplicationName a -ApplicationEnvironment e -Actor @{ type = 'robot' } } |
            Should -Throw '*actor.type must be one of*'
    }

    It 'requires target.type when a target is given' {
        { New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction a -EventResult success -ApplicationName a -ApplicationEnvironment e -Target @{ id = 'x' } } |
            Should -Throw '*target.type is required*'
    }

    It 'rejects more than 64 labels' {
        $labels = @{}
        1..65 | ForEach-Object { $labels["l$_"] = 'v' }
        { New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction a -EventResult success -ApplicationName a -ApplicationEnvironment e -Labels $labels } |
            Should -Throw '*labels may contain at most 64 properties*'
    }
}

Describe 'Test-BowerSecurityEvent' {
    It 'accepts a valid hashtable event' {
        New-TestEvent | Test-BowerSecurityEvent | Should -BeTrue
    }

    It 'accepts a valid JSON string event' {
        (New-TestEvent | ConvertTo-Json -Depth 5) | Test-BowerSecurityEvent | Should -BeTrue
    }

    It 'reports every missing required field' {
        $result = @{ schemaVersion = '1.0.0'; eventId = 'e1' } | Test-BowerSecurityEvent -Detailed
        $result.Valid | Should -BeFalse
        foreach ($field in 'timeGenerated', 'eventCategory', 'eventType', 'eventAction', 'eventResult', 'application') {
            $result.Errors[0] | Should -BeLike "*$field is required*"
        }
    }

    It 'treats property names case-sensitively and suggests the schema name' {
        $event = New-TestEvent
        $event.Remove('eventId')
        $event['EventId'] = 'e1'
        $result = $event | Test-BowerSecurityEvent -Detailed
        $result.Valid | Should -BeFalse
        $result.Errors[0] | Should -BeLike "*property 'EventId' is not allowed; property names are case-sensitive (use 'eventId')*"
    }

    It 'rejects timestamps without an offset' {
        $event = New-TestEvent
        $event.timeGenerated = '2026-10-24 01:02:03'
        ($event | Test-BowerSecurityEvent -Detailed).Errors[0] | Should -BeLike '*timeGenerated must be an RFC 3339 date-time*'
    }

    It 'rejects a schema version other than 1.0.0' {
        $event = New-TestEvent
        $event.schemaVersion = '2.0.0'
        $event | Test-BowerSecurityEvent | Should -BeFalse
    }

    It 'rejects request.statusCode outside 100-599' {
        $event = New-TestEvent
        $event.request = @{ statusCode = 99 }
        ($event | Test-BowerSecurityEvent -Detailed).Errors[0] | Should -BeLike '*request.statusCode must be an integer between 100 and 599*'
    }

    It 'counts length in code points, not UTF-16 units' {
        $event = New-TestEvent
        $event.eventAction = [string]::Concat([System.Linq.Enumerable]::Repeat([char]::ConvertFromUtf32(0x1F600), 128))
        $event | Test-BowerSecurityEvent | Should -BeTrue
    }

    It 'rejects events above the 1 MiB collector limit' {
        $event = New-TestEvent
        $event.attributes = @{ blob = 'x' * 1048576 }
        ($event | Test-BowerSecurityEvent -Detailed).Errors[0] | Should -BeLike '*the collector accepts at most 1048576 bytes*'
    }
}

Describe 'Send-BowerSecurityEvent to a collector' {
    BeforeEach {
        Mock -ModuleName Bower.Events Wait-BowerRetryDelay { }
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            $sent = (Get-TestBodyText $Body) | ConvertFrom-Json
            [pscustomobject]@{ eventId = $sent.eventId; action = 'accept'; queued = $true; duplicate = $false; reasons = @() }
        }
    }

    It 'POSTs one JSON event per request to /v1/events on the loopback collector by default' {
        $results = @(New-TestEvent 'a'; New-TestEvent 'b') | Send-BowerSecurityEvent

        $results.Count | Should -Be 2
        $results[0].Accepted | Should -BeTrue
        $results[0].Queued | Should -BeTrue
        $results[0].Endpoint | Should -Be 'http://127.0.0.1:4319/v1/events'
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 2 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri.AbsoluteUri -eq 'http://127.0.0.1:4319/v1/events' -and
            $ContentType -eq 'application/json; charset=utf-8' -and -not $PesterBoundParameters.ContainsKey('Token') -and $null -eq $Headers -and
            ((Get-TestBodyText $Body) | ConvertFrom-Json).schemaVersion -eq '1.0.0'
        }
    }

    It 'sends the producer token as a SecureString bearer token, never as a header' {
        New-TestEvent | Send-BowerSecurityEvent -Uri https://collector.example.test -Token $script:ProducerToken | Out-Null

        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Authentication -eq 'Bearer' -and $Token -is [securestring] -and
            (ConvertFrom-TestSecureString $Token) -eq $script:PlainToken -and
            $null -eq $Headers -and -not $AllowUnencryptedAuthentication -and
            $Uri.AbsoluteUri -eq 'https://collector.example.test/v1/events'
        }
    }

    It 'allows unencrypted bearer authentication only for loopback http' {
        New-TestEvent | Send-BowerSecurityEvent -Uri http://localhost:4319 -Token $script:ProducerToken | Out-Null
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $AllowUnencryptedAuthentication -eq $true }
    }

    It 'never writes the token to verbose, debug, warning or output streams' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterSeconds 1) } -ParameterFilter { $Body -like '*"evt-retry"*' }
        Mock -ModuleName Bower.Events Wait-BowerRetryDelay { }
        $streams = & {
            try {
                @(New-TestEvent 'evt-0001'; New-TestEvent 'evt-retry') |
                    Send-BowerSecurityEvent -Uri https://collector.example.test -Token $script:ProducerToken -MaximumRetryCount 1 -Verbose -Debug
            }
            catch {
                $_ | Out-String
                $_.Exception | Format-List * -Force | Out-String
            }
        } *>&1 | Out-String
        $streams | Should -Not -BeNullOrEmpty
        $streams | Should -Not -Match ([regex]::Escape($script:PlainToken))
    }

    It 'requires a token for a non-loopback collector' {
        { New-TestEvent | Send-BowerSecurityEvent -Uri https://collector.example.test } | Should -Throw '*non-loopback collector requires -Token*'
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 0
    }

    It 'refuses plain http to a remote collector' {
        { New-TestEvent | Send-BowerSecurityEvent -Uri http://collector.example.test -Token $script:ProducerToken } | Should -Throw '*must use https*'
    }

    It 'refuses URIs with query strings so URL keys are never used' {
        { New-TestEvent | Send-BowerSecurityEvent -Uri 'https://collector.example.test/?code=abc' -Token $script:ProducerToken } | Should -Throw '*must not contain a query string*'
    }

    It 'rejects Entra parameters for the collector target' {
        { New-TestEvent | Send-BowerSecurityEvent -Audience api://x } | Should -Throw '*-Audience cannot be used with -Target Collector*'
    }

    It 'writes a non-terminating error for an invalid event and still sends valid events' {
        $bad = New-TestEvent 'bad'
        $bad.eventResult = 'maybe'
        $output = @(New-TestEvent 'good-1'; $bad; New-TestEvent 'good-2') | Send-BowerSecurityEvent -ErrorAction Continue 2>&1
        $sendErrors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })

        $results.EventId | Should -Be @('good-1', 'good-2')
        $sendErrors.Count | Should -Be 1
        $sendErrors[0].FullyQualifiedErrorId | Should -BeLike 'BowerSecurityEventInvalid*'
        $sendErrors[0].Exception.Message | Should -BeLike "*Security event 'bad' is invalid: eventResult must be one of*"
    }

    It 'does not send anything with -WhatIf' {
        @(New-TestEvent 'a'; New-TestEvent 'b'; New-TestEvent 'c') | Send-BowerSecurityEvent -BatchSize 2 -WhatIf
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 0
    }

    It 'sends in batches and waits between batches' {
        $events = 1..5 | ForEach-Object { New-TestEvent "e$_" }
        $results = $events | Send-BowerSecurityEvent -BatchSize 2 -BatchDelayMilliseconds 250
        $results.Count | Should -Be 5
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 5 -Exactly
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 2 -Exactly -ParameterFilter { $Seconds -eq 0.25 }
    }

    It 'returns policy rejections as unaccepted results with reasons' {
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 422 -Body '{"eventId":"evt-0001","action":"reject","queued":false,"duplicate":false,"reasons":["event-type-not-allowed"]}')
        }
        $result = New-TestEvent | Send-BowerSecurityEvent -WarningVariable warnings -WarningAction SilentlyContinue
        $result.Accepted | Should -BeFalse
        $result.StatusCode | Should -Be 422
        $result.Action | Should -Be 'reject'
        $result.Reasons | Should -Be @('event-type-not-allowed')
        $result.Message | Should -Be 'HTTP 422 (UnprocessableEntity): event-type-not-allowed'
        $warnings.Count | Should -Be 1
    }

    It 'surfaces event identity conflict remediation' {
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            throw (New-HttpErrorRecord -StatusCode 409 -Body '{"eventId":"evt-0001","action":"reject","queued":false,"duplicate":false,"reasons":["event-id-conflict"],"remediation":"Repair the producer mapping."}')
        }
        $result = New-TestEvent | Send-BowerSecurityEvent -WarningAction SilentlyContinue
        $result.StatusCode | Should -Be 409
        $result.Remediation | Should -Be 'Repair the producer mapping.'
    }

    It 'propagates the API error message for producer scope denials' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 403 -Body '{"error":"Producer is not authorized for this event identity."}') }
        $result = New-TestEvent | Send-BowerSecurityEvent -WarningAction SilentlyContinue
        $result.Message | Should -Be 'HTTP 403 (Forbidden): Producer is not authorized for this event identity.'
    }

    It 'stops with a terminating error on 401 without retrying' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 401) }
        { @(New-TestEvent 'a'; New-TestEvent 'b') | Send-BowerSecurityEvent -Uri https://c.example.test -Token $script:ProducerToken } |
            Should -Throw "*rejected the credential*Event 'a' and later events were not sent*"
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 0
    }

    It 'stops on server errors without retrying' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 500) }
        { New-TestEvent | Send-BowerSecurityEvent } | Should -Throw '*failed (HTTP 500 (InternalServerError).)*'
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly
    }

    It 'rethrows transport failures that have no HTTP response' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw [System.Net.Http.HttpRequestException]::new('Connection refused (127.0.0.1:4319)') }
        { New-TestEvent | Send-BowerSecurityEvent } | Should -Throw '*Connection refused*'
    }
}

Describe 'Send-BowerSecurityEvent retry and backoff' {
    BeforeEach {
        $script:attempts = 0
        Mock -ModuleName Bower.Events Wait-BowerRetryDelay { }
    }

    It 'retries 429 honouring Retry-After and then succeeds' {
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            $script:attempts++
            if ($script:attempts -le 2) { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterSeconds 7) }
            [pscustomobject]@{ eventId = 'evt-0001'; action = 'accept'; queued = $true; duplicate = $false; reasons = @() }
        }
        $result = New-TestEvent | Send-BowerSecurityEvent
        $result.Accepted | Should -BeTrue
        $result.Attempts | Should -Be 3
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 2 -Exactly -ParameterFilter { $Seconds -eq 7 }
    }

    It 'retries 503 with exponential backoff when Retry-After is absent' {
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            $script:attempts++
            if ($script:attempts -le 3) { throw (New-HttpErrorRecord -StatusCode 503 -Body '{"error":"Collector queue is at capacity; retry later."}') }
            [pscustomobject]@{ eventId = 'evt-0001'; action = 'accept'; queued = $true; duplicate = $false; reasons = @() }
        }
        New-TestEvent | Send-BowerSecurityEvent | Out-Null
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 1 -Exactly -ParameterFilter { $Seconds -eq 1 }
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 1 -Exactly -ParameterFilter { $Seconds -eq 4 }
    }

    It 'caps every delay at -MaximumRetryDelaySeconds' {
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            $script:attempts++
            if ($script:attempts -eq 1) { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterSeconds 3600) }
            if ($script:attempts -eq 2) { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterDate ([datetimeoffset]::UtcNow.AddHours(2))) }
            [pscustomobject]@{ eventId = 'evt-0001'; action = 'accept'; queued = $true; duplicate = $false; reasons = @() }
        }
        New-TestEvent | Send-BowerSecurityEvent -MaximumRetryDelaySeconds 30 | Out-Null
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 2 -Exactly -ParameterFilter { $Seconds -eq 30 }
    }

    It 'gives up after -MaximumRetryCount retries with a terminating backpressure error' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 503 -Body '{"error":"Collector queue is at capacity; retry later."}') }
        { @(New-TestEvent 'first'; New-TestEvent 'second') | Send-BowerSecurityEvent -MaximumRetryCount 2 } |
            Should -Throw "*still applying backpressure after 3 attempt(s) (HTTP 503 (ServiceUnavailable): Collector queue is at capacity; retry later.) Event 'first' and later events were not sent*"
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 3 -Exactly
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 2 -Exactly
    }

    It 'does not retry when -MaximumRetryCount is 0' {
        Mock -ModuleName Bower.Events Invoke-RestMethod { throw (New-HttpErrorRecord -StatusCode 429) }
        { New-TestEvent | Send-BowerSecurityEvent -MaximumRetryCount 0 } | Should -Throw '*backpressure after 1 attempt(s)*'
        Should -Invoke -ModuleName Bower.Events Wait-BowerRetryDelay -Times 0
    }

    It 'bounds -MaximumRetryCount and -MaximumRetryDelaySeconds' {
        { New-TestEvent | Send-BowerSecurityEvent -MaximumRetryCount 11 } | Should -Throw
        { New-TestEvent | Send-BowerSecurityEvent -MaximumRetryDelaySeconds 301 } | Should -Throw
        { New-TestEvent | Send-BowerSecurityEvent -BatchSize 501 } | Should -Throw
    }
}

Describe 'Send-BowerSecurityEvent to the Azure Function' {
    BeforeEach {
        Mock -ModuleName Bower.Events Invoke-RestMethod { [pscustomobject]@{ eventId = 'evt-0001'; action = 'accept'; queued = $true; duplicate = $false; reasons = @() } }
        Mock -ModuleName Bower.Events Get-BowerAzAccessToken {
            [pscustomobject]@{ Token = (New-TestSecureString 'entra-token-SECRET-abc'); ExpiresOn = [datetimeoffset]::UtcNow.AddHours(1) }
        }
    }

    It 'acquires an Entra token through Az.Accounts for the audience and appends /v1/events' {
        New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Uri https://bower-fn.azurewebsites.net/api -Audience api://bower-function -TenantId 11111111-2222-3333-4444-555555555555 | Out-Null

        Should -Invoke -ModuleName Bower.Events Get-BowerAzAccessToken -Times 1 -Exactly -ParameterFilter {
            $ResourceUrl -eq 'api://bower-function' -and $TenantId -eq '11111111-2222-3333-4444-555555555555'
        }
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri.AbsoluteUri -eq 'https://bower-fn.azurewebsites.net/api/v1/events' -and $Authentication -eq 'Bearer' -and
            (ConvertFrom-TestSecureString $Token) -eq 'entra-token-SECRET-abc'
        }
    }

    It 'reuses a fresh token across events' {
        @(New-TestEvent 'a'; New-TestEvent 'b'; New-TestEvent 'c') | Send-BowerSecurityEvent -Target AzureFunction -Uri https://fn.example.test -Audience api://fn | Out-Null
        Should -Invoke -ModuleName Bower.Events Get-BowerAzAccessToken -Times 1 -Exactly
    }

    It 'accepts -AccessToken without Az.Accounts' {
        New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Uri https://fn.example.test -AccessToken (New-TestSecureString 'static-token') | Out-Null
        Should -Invoke -ModuleName Bower.Events Get-BowerAzAccessToken -Times 0
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -ParameterFilter { (ConvertFrom-TestSecureString $Token) -eq 'static-token' }
    }

    It 'accepts a token provider script block' {
        New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Uri https://fn.example.test -TokenProvider { New-TestSecureString 'provided-token' } | Out-Null
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -ParameterFilter { (ConvertFrom-TestSecureString $Token) -eq 'provided-token' }
    }

    It 'requires a credential source and a URI' {
        { New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Uri https://fn.example.test } | Should -Throw '*requires -AccessToken, -TokenProvider or -Audience*'
        { New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Audience api://fn } | Should -Throw '*-Uri is required*'
    }

    It 'rejects the collector producer token for the Function target' {
        { New-TestEvent | Send-BowerSecurityEvent -Target AzureFunction -Uri https://fn.example.test -Token $script:ProducerToken } | Should -Throw '*-Token cannot be used with -Target AzureFunction*'
    }
}

Describe 'Get-BowerAzAccessToken' {
    BeforeAll {
        function global:Get-AzAccessToken {
            param([string] $ResourceUrl, [string] $TenantId, [switch] $AsSecureString)
            $global:BowerTestAzCall = @{ ResourceUrl = $ResourceUrl; TenantId = $TenantId; AsSecureString = [bool]$AsSecureString }
            [pscustomobject]@{ Token = 'az-plain-token'; ExpiresOn = [datetimeoffset]::UtcNow.AddMinutes(30) }
        }
    }
    AfterAll {
        Remove-Item -Path Function:\global:Get-AzAccessToken -ErrorAction SilentlyContinue
        Remove-Variable -Name BowerTestAzCall -Scope Global -ErrorAction SilentlyContinue
    }

    It 'requests a SecureString token and converts string tokens immediately' {
        $token = InModuleScope Bower.Events { Get-BowerAzAccessToken -ResourceUrl 'api://fn' -TenantId 't1' }
        $token.Token | Should -BeOfType [securestring]
        ConvertFrom-TestSecureString $token.Token | Should -Be 'az-plain-token'
        $token.ExpiresOn | Should -BeOfType [datetimeoffset]
        $global:BowerTestAzCall.AsSecureString | Should -BeTrue
        $global:BowerTestAzCall.ResourceUrl | Should -Be 'api://fn'
    }

    It 'explains how to proceed when Az.Accounts is missing' {
        Mock -ModuleName Bower.Events Get-Command { $null } -ParameterFilter { $Name -eq 'Get-AzAccessToken' }
        Mock -ModuleName Bower.Events Import-Module { } -ParameterFilter { $Name -eq 'Az.Accounts' }
        { InModuleScope Bower.Events { Get-BowerAzAccessToken -ResourceUrl 'api://fn' } } | Should -Throw '*Az.Accounts is not available*-AccessToken*'
    }
}

Describe 'Send-BowerSecurityEvent to the Lambda Function URL' {
    BeforeEach {
        Mock -ModuleName Bower.Events Invoke-RestMethod { [pscustomobject]@{ accepted = 1 } }
        Mock -ModuleName Bower.Events Get-BowerAwsCredential {
            [pscustomobject]@{
                AccessKeyId     = 'AKIDEXAMPLE'
                SecretAccessKey = New-TestSecureString 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
                SessionToken    = New-TestSecureString 'session-token-EXAMPLE'
            }
        }
    }

    It 'signs the request with SigV4 for the lambda service and region inferred from the URL' {
        $result = New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri https://abc123def.lambda-url.ap-southeast-2.on.aws -AwsProfileName bower
        $result.Accepted | Should -BeTrue

        Should -Invoke -ModuleName Bower.Events Get-BowerAwsCredential -Times 1 -Exactly -ParameterFilter { $ProfileName -eq 'bower' }
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri.AbsoluteUri -eq 'https://abc123def.lambda-url.ap-southeast-2.on.aws/v1/events' -and
            -not $PesterBoundParameters.ContainsKey('Token') -and $Body -is [byte[]] -and $ContentType -eq 'application/json' -and
            $Headers.Authorization -match '^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/\d{8}/ap-southeast-2/lambda/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$' -and
            $Headers['x-amz-date'] -match '^\d{8}T\d{6}Z$' -and
            $Headers['x-amz-security-token'] -eq 'session-token-EXAMPLE' -and
            $Headers['x-amz-content-sha256'] -eq [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Body)).ToLowerInvariant()
        }
    }

    It 'signs every retry attempt again' {
        $script:lambdaAttempts = 0
        Mock -ModuleName Bower.Events Wait-BowerRetryDelay { }
        Mock -ModuleName Bower.Events Invoke-RestMethod {
            $script:lambdaAttempts++
            if ($script:lambdaAttempts -eq 1) { throw (New-HttpErrorRecord -StatusCode 429 -RetryAfterSeconds 1) }
            [pscustomobject]@{ accepted = 1 }
        }
        New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri https://abc123def.lambda-url.ap-southeast-2.on.aws | Out-Null
        Should -Invoke -ModuleName Bower.Events Invoke-RestMethod -Times 2 -Exactly -ParameterFilter { $Headers.Authorization -like 'AWS4-HMAC-SHA256 *' }
    }

    It 'never writes the secret key or session token to verbose or debug output' {
        $streams = & { New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri https://abc123def.lambda-url.ap-southeast-2.on.aws -Verbose -Debug } *>&1 | Out-String
        $streams | Should -Not -Match 'wJalrXUtnFEMI'
        $streams | Should -Not -Match 'session-token-EXAMPLE'
    }

    It 'requires https and a region it can infer or is given' {
        { New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri http://127.0.0.1:9000 } | Should -Throw '*require https*'
        { New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri https://lambda.example.test } | Should -Throw '*pass -AwsRegion*'
    }

    It 'rejects bearer token parameters for the Lambda target' {
        { New-TestEvent | Send-BowerSecurityEvent -Target Lambda -Uri https://abc.lambda-url.ap-southeast-2.on.aws -Token $script:ProducerToken } | Should -Throw '*-Token cannot be used with -Target Lambda*'
    }

}

Describe 'Get-BowerAwsCredential' {
    It 'gives a clear error when AWS.Tools.Common is not installed' {
        Mock -ModuleName Bower.Events Get-Command { $null } -ParameterFilter { $Name -eq 'Get-AWSCredential' }
        Mock -ModuleName Bower.Events Import-Module { } -ParameterFilter { $Name -eq 'AWS.Tools.Common' }
        { InModuleScope Bower.Events { Get-BowerAwsCredential } } | Should -Throw '*needs AWS.Tools.Common*'
    }
}

Describe 'AWS Signature Version 4' {
    It 'matches the AWS documentation test vector (IAM ListUsers)' {
        $authorization = InModuleScope Bower.Events {
            $headers = [ordered]@{
                'Content-Type' = 'application/x-www-form-urlencoded; charset=utf-8'
                'Host'         = 'iam.amazonaws.com'
                'X-Amz-Date'   = '20150830T123600Z'
            }
            Get-BowerSigV4Authorization -Method GET -Uri 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08' -Headers $headers `
                -Payload ([byte[]]@()) -Region 'us-east-1' -Service 'iam' -AccessKeyId 'AKIDEXAMPLE' `
                -SecretAccessKey (ConvertTo-BowerSecureString -Value 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY') -AmzDate '20150830T123600Z'
        }
        $authorization | Should -BeExactly 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7'
    }
}
