function Resolve-BowerEventEndpoint {
    <# Returns the /v1/events URI for a base or full endpoint URI. #>
    [CmdletBinding()]
    [OutputType([uri])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri
    )

    if (-not $Uri.IsAbsoluteUri) {
        throw [System.ArgumentException]::new('Uri must be an absolute http(s) URI.')
    }
    if ($Uri.Query -or $Uri.Fragment) {
        throw [System.ArgumentException]::new('Uri must not contain a query string or fragment; authenticate with a bearer, Entra or SigV4 credential instead of URL keys.')
    }

    $path = $Uri.AbsolutePath.TrimEnd('/')
    if (-not $path.EndsWith('/v1/events', [System.StringComparison]::Ordinal)) {
        $path = "$path/v1/events"
    }
    $builder = [System.UriBuilder]::new($Uri)
    $builder.Path = $path
    $builder.Uri
}

function Get-BowerEventAuthentication {
    <# Returns the bearer token (SecureString or $null) for the next request, refreshing when needed. #>
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Context
    )

    if ($Context.Target -eq 'Lambda') {
        return $null
    }
    if ($Context.StaticToken) {
        return $Context.StaticToken
    }
    if (-not (Test-BowerTokenFresh -Token $Context.Auth)) {
        if ($Context.TokenProvider) {
            $Context.Auth = Invoke-BowerTokenProvider -TokenProvider $Context.TokenProvider
        }
        elseif ($Context.Audience) {
            $Context.Auth = Get-BowerAzAccessToken -ResourceUrl $Context.Audience -TenantId $Context.TenantId
        }
        else {
            return $null
        }
    }
    $Context.Auth.Token
}

function New-BowerEventSubmissionResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    [OutputType('Bower.EventSubmission')]
    param(
        [Parameter(Mandatory)]
        [string] $EventId,

        [Parameter(Mandatory)]
        [hashtable] $Context,

        [Parameter(Mandatory)]
        [bool] $Accepted,

        [AllowNull()]
        [object] $Content,

        [AllowNull()]
        [object] $StatusCode,

        [AllowNull()]
        [string] $Message,

        [int] $Attempts = 1
    )

    $names = if ($Content -is [System.Management.Automation.PSCustomObject]) { @($Content.PSObject.Properties.Name) } else { @() }
    [pscustomobject]@{
        PSTypeName  = 'Bower.EventSubmission'
        EventId     = if ($names -contains 'eventId' -and $Content.eventId) { [string]$Content.eventId } else { $EventId }
        Target      = $Context.Target
        Endpoint    = $Context.Uri.GetLeftPart([System.UriPartial]::Path)
        Accepted    = $Accepted
        StatusCode  = $StatusCode
        Action      = if ($names -contains 'action') { $Content.action } else { $null }
        Queued      = if ($names -contains 'queued') { [bool]$Content.queued } else { $null }
        Duplicate   = if ($names -contains 'duplicate') { [bool]$Content.duplicate } else { $null }
        Reasons     = if ($names -contains 'reasons') { @($Content.reasons) } else { @() }
        Remediation = if ($names -contains 'remediation') { $Content.remediation } else { $null }
        Message     = $Message
        Attempts    = $Attempts
    }
}

function Send-BowerEventItem {
    <#
    Sends one prepared event. Returns a Bower.EventSubmission for collector decisions
    (2xx, 400, 403, 409, 413, 422). Throws for authentication failure, exhausted
    backpressure (429/503) and server errors, because later events would fail the same way.
    #>
    [CmdletBinding()]
    [OutputType('Bower.EventSubmission')]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Item,

        [Parameter(Mandatory)]
        [hashtable] $Context
    )

    $request = @{
        Method                   = 'POST'
        Uri                      = $Context.Uri
        MaximumRetryCount        = $Context.MaximumRetryCount
        MaximumRetryDelaySeconds = $Context.MaximumRetryDelaySeconds
        TimeoutSec               = $Context.TimeoutSec
    }
    if ($Context.Target -eq 'Lambda') {
        $request.Body = $Item.Bytes
        $request.ContentType = 'application/json'
        $request.HeaderFactory = ${function:Get-BowerLambdaSignedHeader}
        $request.HeaderFactoryArgument = @{
            Uri           = $Context.Uri
            Payload       = $Item.Bytes
            Region        = $Context.Region
            AwsCredential = $Context.AwsCredential
        }
    }
    else {
        $request.Body = $Item.Json
        $request.Token = Get-BowerEventAuthentication -Context $Context
    }

    $response = Invoke-BowerHttpRequest @request
    if ($response.Succeeded) {
        return New-BowerEventSubmissionResult -EventId $Item.EventId -Context $Context -Accepted $true `
            -Content $response.Content -Attempts $response.Attempts
    }

    $status = [int]$response.StatusCode
    if ($status -eq 401) {
        throw [System.UnauthorizedAccessException]::new(
            "The $($Context.Target) rejected the credential ($($response.Message)) Event '$($Item.EventId)' and later events were not sent.")
    }
    if ($status -in 429, 503) {
        throw [System.InvalidOperationException]::new(
            "The $($Context.Target) is still applying backpressure after $($response.Attempts) attempt(s) ($($response.Message)) Event '$($Item.EventId)' and later events were not sent; retry later with the same event IDs.")
    }
    if ($status -ge 500) {
        throw [System.InvalidOperationException]::new(
            "The $($Context.Target) failed ($($response.Message)) Event '$($Item.EventId)' and later events were not sent.")
    }

    $content = $null
    if ($response.Body) {
        try {
            $content = $response.Body | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $content = $null
        }
    }
    New-BowerEventSubmissionResult -EventId $Item.EventId -Context $Context -Accepted $false -Content $content `
        -StatusCode $status -Message $response.Message -Attempts $response.Attempts
}
