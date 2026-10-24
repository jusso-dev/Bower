function Send-BowerSecurityEvent {
    <#
    .SYNOPSIS
    Sends security events to a Bower collector, the Bower Azure Function or the Bower Lambda.

    .DESCRIPTION
    Validates each event against the envelope schema, then POSTs it to the target's
    /v1/events endpoint, one event per request (the collector contract). Input is
    processed in batches of -BatchSize events; each batch is confirmed once with
    ShouldProcess (-WhatIf lists batches without sending), and -BatchDelayMilliseconds
    can space batches to stay below the collector's ingest rate limit.

    429 and 503 responses are retried up to -MaximumRetryCount times, honouring
    Retry-After and capped by -MaximumRetryDelaySeconds; without Retry-After the delay is
    1, 2, 4, ... seconds. If backpressure persists, a 401 is returned or the target fails
    with a 5xx status, sending stops with a terminating error naming the first unsent
    event; resend later with the same event IDs (the collector de-duplicates them).

    Collector decisions are returned per event as Bower.EventSubmission objects. Accepted
    is $false for policy rejections (422), invalid events (400), producer scope denials
    (403), event identity conflicts (409, with remediation) and oversized events (413).

    Targets:
    - Collector (default): http://127.0.0.1:4319 by default. -Token is the producer
      bearer token; it is required for non-loopback collectors, which must use https.
    - AzureFunction: the Bower Azure Function collector (same /v1/events contract) with an
      Entra access token from -AccessToken, -TokenProvider, or Az.Accounts
      (Get-AzAccessToken -ResourceUrl <Audience>).
    - Lambda: the Bower CloudTrail Lake Lambda Function URL (AuthType AWS_IAM). Requests are
      SigV4-signed with credentials from AWS.Tools.Common (-AwsProfileName or the SDK
      default chain). Requires https.

    Tokens are handled as SecureString and never written to output, verbose or debug
    streams. TLS certificate validation is never disabled.

    .PARAMETER InputObject
    Events from New-BowerSecurityEvent, hashtables, PSCustomObjects or JSON strings.

    .PARAMETER Target
    Collector, AzureFunction or Lambda.

    .PARAMETER Uri
    Base or full endpoint URI. /v1/events is appended when missing. Query strings are
    rejected so URL keys are never used or echoed.

    .PARAMETER Token
    Collector producer bearer token (SecureString).

    .PARAMETER AccessToken
    Entra access token for the Azure Function target (SecureString).

    .PARAMETER TokenProvider
    Script block returning a SecureString token (or an object with Token and ExpiresOn).
    It is invoked again when the returned token is about to expire.

    .PARAMETER Audience
    Entra resource (application ID URI) of the Azure Function, used with Az.Accounts.

    .PARAMETER TenantId
    Entra tenant for Az.Accounts token acquisition.

    .PARAMETER AwsProfileName
    AWS credential profile for the Lambda target.

    .PARAMETER AwsRegion
    AWS region for SigV4. Inferred from *.lambda-url.<region>.on.aws hosts when omitted.

    .PARAMETER BatchSize
    Events per batch (1-500, default 100).

    .PARAMETER BatchDelayMilliseconds
    Pause between batches (0-60000, default 0).

    .PARAMETER MaximumRetryCount
    Retries per event on 429/503 (0-10, default 4).

    .PARAMETER MaximumRetryDelaySeconds
    Upper bound for any single retry delay (1-300, default 60).

    .PARAMETER TimeoutSec
    Per-request timeout (1-600, default 100).

    .EXAMPLE
    New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction sign-in `
        -EventResult success -ApplicationName payroll -ApplicationEnvironment production |
        Send-BowerSecurityEvent

    Sends one event to the loopback collector (no token required on loopback when the
    collector allows it).

    .EXAMPLE
    $token = Get-Secret -Name bower-ingest   # SecretManagement returns a SecureString
    Get-Content ./events.jsonl | Send-BowerSecurityEvent -Uri https://collector.example.gov.au -Token $token -BatchSize 200

    Sends newline-delimited JSON events to a remote collector with a producer token.

    .EXAMPLE
    $events | Send-BowerSecurityEvent -Target AzureFunction -Uri https://bower-fn.azurewebsites.net/api `
        -Audience api://11111111-2222-3333-4444-555555555555

    Sends to the Azure Function collector with a token acquired through Az.Accounts.

    .EXAMPLE
    $events | Send-BowerSecurityEvent -Target Lambda -Uri https://abc123.lambda-url.ap-southeast-2.on.aws -AwsProfileName bower

    Sends SigV4-signed requests to the CloudTrail Lake Lambda Function URL.

    .EXAMPLE
    $events | Send-BowerSecurityEvent -WhatIf

    Validates the events and shows the batches that would be sent, without sending.

    .OUTPUTS
    Bower.EventSubmission
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType('Bower.EventSubmission')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object] $InputObject,

        [ValidateSet('Collector', 'AzureFunction', 'Lambda')]
        [string] $Target = 'Collector',

        [uri] $Uri,

        [securestring] $Token,

        [securestring] $AccessToken,

        [scriptblock] $TokenProvider,

        [ValidateNotNullOrEmpty()]
        [string] $Audience,

        [ValidateNotNullOrEmpty()]
        [string] $TenantId,

        [ValidateNotNullOrEmpty()]
        [string] $AwsProfileName,

        [ValidatePattern('^[a-z]{2}(-[a-z]+)+-\d+$')]
        [string] $AwsRegion,

        [ValidateRange(1, 500)]
        [int] $BatchSize = 100,

        [ValidateRange(0, 60000)]
        [int] $BatchDelayMilliseconds = 0,

        [ValidateRange(0, 10)]
        [int] $MaximumRetryCount = 4,

        [ValidateRange(1, 300)]
        [int] $MaximumRetryDelaySeconds = 60,

        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 100
    )

    begin {
        function Write-TerminatingError([System.Exception] $Exception, [string] $ErrorId, [System.Management.Automation.ErrorCategory] $Category) {
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($Exception, $ErrorId, $Category, $null))
        }

        $allowed = @{
            Collector     = @('Token', 'TokenProvider')
            AzureFunction = @('AccessToken', 'TokenProvider', 'Audience', 'TenantId')
            Lambda        = @('AwsProfileName', 'AwsRegion')
        }
        $credentialParameters = 'Token', 'AccessToken', 'TokenProvider', 'Audience', 'TenantId', 'AwsProfileName', 'AwsRegion'
        foreach ($name in $credentialParameters) {
            if ($PSBoundParameters.ContainsKey($name) -and $allowed[$Target] -notcontains $name) {
                Write-TerminatingError ([System.ArgumentException]::new("-$name cannot be used with -Target $Target.")) 'BowerEventParameterConflict' InvalidArgument
            }
        }

        if (-not $Uri) {
            if ($Target -ne 'Collector') {
                Write-TerminatingError ([System.ArgumentException]::new("-Uri is required for -Target $Target.")) 'BowerEventUriRequired' InvalidArgument
            }
            $Uri = [uri]'http://127.0.0.1:4319'
        }

        try {
            $endpoint = Resolve-BowerEventEndpoint -Uri $Uri
            Assert-BowerTransportUri -Uri $endpoint
            if ($Target -eq 'Lambda' -and $endpoint.Scheme -ne 'https') {
                throw [System.ArgumentException]::new('Lambda Function URLs require https.')
            }
        }
        catch {
            Write-TerminatingError $_.Exception 'BowerEventUriInvalid' InvalidArgument
        }

        $sources = @('AccessToken', 'TokenProvider', 'Audience', 'Token' | Where-Object { $PSBoundParameters.ContainsKey($_) })
        if ($sources.Count -gt 1) {
            Write-TerminatingError ([System.ArgumentException]::new("Use only one of -$($sources -join ', -').")) 'BowerEventParameterConflict' InvalidArgument
        }
        if ($Target -eq 'AzureFunction' -and $sources.Count -eq 0) {
            Write-TerminatingError ([System.ArgumentException]::new('-Target AzureFunction requires -AccessToken, -TokenProvider or -Audience.')) 'BowerEventCredentialRequired' InvalidArgument
        }
        if ($Target -eq 'Collector' -and $sources.Count -eq 0 -and -not (Test-BowerLoopbackUri -Uri $endpoint)) {
            Write-TerminatingError ([System.ArgumentException]::new('A non-loopback collector requires -Token or -TokenProvider.')) 'BowerEventCredentialRequired' InvalidArgument
        }

        $context = @{
            Target                   = $Target
            Uri                      = $endpoint
            StaticToken              = if ($Token) { $Token } elseif ($AccessToken) { $AccessToken } else { $null }
            TokenProvider            = $TokenProvider
            Audience                 = $Audience
            TenantId                 = $TenantId
            Auth                     = $null
            AwsProfileName           = $AwsProfileName
            Region                   = $null
            AwsCredential            = $null
            MaximumRetryCount        = $MaximumRetryCount
            MaximumRetryDelaySeconds = $MaximumRetryDelaySeconds
            TimeoutSec               = $TimeoutSec
        }
        if ($Target -eq 'Lambda') {
            try {
                $context.Region = Get-BowerLambdaRegion -Uri $endpoint -Region $AwsRegion
            }
            catch {
                Write-TerminatingError $_.Exception 'BowerEventRegionRequired' InvalidArgument
            }
        }

        $display = $endpoint.GetLeftPart([System.UriPartial]::Path)
        $batch = [System.Collections.Generic.List[object]]::new()
        $context.BatchNumber = 0

        function Send-PendingBatch {
            if ($batch.Count -eq 0) {
                return
            }
            $items = $batch.ToArray()
            $batch.Clear()
            $context.BatchNumber++
            $batchNumber = $context.BatchNumber

            if (-not $PSCmdlet.ShouldProcess($display, "Send $($items.Count) security event(s) (batch $batchNumber)")) {
                return
            }
            if ($batchNumber -gt 1 -and $BatchDelayMilliseconds -gt 0) {
                Wait-BowerRetryDelay -Seconds ($BatchDelayMilliseconds / 1000)
            }

            try {
                if ($Target -eq 'Lambda' -and $null -eq $context.AwsCredential) {
                    $context.AwsCredential = Get-BowerAwsCredential -ProfileName $context.AwsProfileName
                }
                foreach ($item in $items) {
                    $result = Send-BowerEventItem -Item $item -Context $context
                    if (-not $result.Accepted) {
                        Write-Warning "Event '$($result.EventId)' was not accepted: $($result.Message)"
                    }
                    $result
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-TerminatingError $_.Exception 'BowerEventAuthenticationFailed' AuthenticationError
            }
            catch {
                Write-TerminatingError $_.Exception 'BowerEventSendFailed' ConnectionError
            }
        }
    }

    process {
        try {
            $item = ConvertTo-BowerEventJson -InputObject $InputObject
        }
        catch [System.ArgumentException] {
            $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new($_.Exception, 'BowerSecurityEventInvalid', 'InvalidData', $null))
            return
        }

        $batch.Add($item)
        if ($batch.Count -ge $BatchSize) {
            Send-PendingBatch
        }
    }

    end {
        Send-PendingBatch
    }
}
