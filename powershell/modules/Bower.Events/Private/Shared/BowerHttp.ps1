# Shared by Bower.Events and Bower.Management. Keep both copies byte-identical
# (powershell/tests/Repository.Tests.ps1 enforces it).
#
# Bearer tokens are passed to Invoke-RestMethod as SecureString (-Authentication Bearer
# -Token), so they never appear in a header dictionary, verbose or debug output.
# TLS certificate validation is never disabled.

function Test-BowerLoopbackUri {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri
    )

    $Uri.IsAbsoluteUri -and $Uri.IsLoopback
}

function Assert-BowerTransportUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [uri] $Uri,

        [string] $Name = 'Uri'
    )

    if ($null -eq $Uri -or -not $Uri.IsAbsoluteUri) {
        throw [System.ArgumentException]::new("$Name must be an absolute http(s) URI.")
    }
    if ($Uri.UserInfo) {
        throw [System.ArgumentException]::new("$Name must not contain credentials.")
    }
    if ($Uri.Scheme -eq 'https') {
        return
    }
    if ($Uri.Scheme -eq 'http' -and (Test-BowerLoopbackUri -Uri $Uri)) {
        return
    }
    throw [System.ArgumentException]::new("$Name must use https; plain http is allowed only for loopback hosts.")
}

function Get-BowerHttpStatusCode {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $response = $ErrorRecord.Exception.Response
    if ($null -ne $response -and $null -ne $response.StatusCode) {
        return [int]$response.StatusCode
    }
    $null
}

function Get-BowerRetryDelay {
    <#
    Seconds to wait before the next attempt: Retry-After (delta or date) when present,
    otherwise exponential backoff (1, 2, 4, ...). Always clamped to [0, MaximumSeconds].
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [AllowNull()]
        [System.Management.Automation.ErrorRecord] $ErrorRecord,

        [Parameter(Mandatory)]
        [int] $Attempt,

        [Parameter(Mandatory)]
        [int] $MaximumSeconds
    )

    $seconds = [math]::Pow(2, $Attempt)
    $retryAfter = $null
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.Exception.Response) {
        $retryAfter = $ErrorRecord.Exception.Response.Headers.RetryAfter
    }
    if ($null -ne $retryAfter) {
        if ($null -ne $retryAfter.Delta) {
            $seconds = $retryAfter.Delta.TotalSeconds
        }
        elseif ($null -ne $retryAfter.Date) {
            $seconds = ($retryAfter.Date - [datetimeoffset]::UtcNow).TotalSeconds
        }
    }

    [math]::Min([math]::Max($seconds, 0), $MaximumSeconds)
}

function Wait-BowerRetryDelay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double] $Seconds
    )

    Start-Sleep -Milliseconds ([int][math]::Ceiling($Seconds * 1000))
}

function Get-BowerApiErrorMessage {
    <#
    Builds a metadata-only message from an API error body: Bower `error`, ASP.NET
    validation `errors`, collector `reasons`, or problem `title`. Non-JSON bodies are not
    echoed, because they may be proxy pages or carry request detail.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $StatusCode,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Body
    )

    $detail = $null
    $json = $null
    if (-not [string]::IsNullOrWhiteSpace($Body)) {
        try {
            $json = $Body | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $json = $null
        }
    }

    if ($json -is [System.Management.Automation.PSCustomObject]) {
        $names = @($json.PSObject.Properties.Name)
        if ($names -contains 'error' -and $json.error -is [string]) {
            $detail = $json.error
        }
        elseif ($names -contains 'errors' -and $json.errors -is [System.Management.Automation.PSCustomObject]) {
            $detail = @(
                foreach ($property in $json.errors.PSObject.Properties) {
                    '{0}: {1}' -f $property.Name, (@($property.Value) -join ' ')
                }
            ) -join '; '
        }
        elseif ($names -contains 'reasons' -and @($json.reasons).Count -gt 0) {
            $detail = @($json.reasons) -join ', '
        }
        elseif ($names -contains 'title' -and $json.title -is [string]) {
            $detail = $json.title
        }
    }

    $reason = [System.Net.HttpStatusCode]$StatusCode
    if ($detail) {
        "HTTP $StatusCode ($reason): $detail"
    }
    else {
        "HTTP $StatusCode ($reason)."
    }
}

function Invoke-BowerHttpRequest {
    <#
    Sends one JSON request with bounded retry on the configured status codes (429/503 by
    default), honouring Retry-After. Returns { Succeeded, StatusCode, Content, Body,
    Message, Attempts }. Throws only when no HTTP response was received.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string] $Method,

        [Parameter(Mandatory)]
        [uri] $Uri,

        [AllowNull()]
        [object] $Body,

        [AllowNull()]
        [securestring] $Token,

        # Returns extra headers per attempt (for example a fresh SigV4 signature).
        [scriptblock] $HeaderFactory,

        [hashtable] $HeaderFactoryArgument = @{},

        [string] $ContentType = 'application/json; charset=utf-8',

        [ValidateRange(0, 10)]
        [int] $MaximumRetryCount = 4,

        [ValidateRange(1, 300)]
        [int] $MaximumRetryDelaySeconds = 60,

        [int[]] $RetryStatusCode = @(429, 503),

        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 100
    )

    $attempt = 0
    while ($true) {
        $request = @{
            Method      = $Method
            Uri         = $Uri
            TimeoutSec  = $TimeoutSec
            ErrorAction = 'Stop'
            Verbose     = $false
            Debug       = $false
        }
        if ($null -ne $Body) {
            $request.Body = $Body
            $request.ContentType = $ContentType
        }
        if ($null -ne $Token) {
            $request.Authentication = 'Bearer'
            $request.Token = $Token
            if ($Uri.Scheme -eq 'http' -and (Test-BowerLoopbackUri -Uri $Uri)) {
                $request.AllowUnencryptedAuthentication = $true
            }
        }
        if ($HeaderFactory) {
            $request.Headers = & $HeaderFactory @HeaderFactoryArgument
        }

        Write-Verbose ('{0} {1} (attempt {2})' -f $Method, $Uri.GetLeftPart([System.UriPartial]::Path), ($attempt + 1))
        try {
            $content = Invoke-RestMethod @request
            return [pscustomobject]@{
                Succeeded  = $true
                StatusCode = $null
                Content    = $content
                Body       = $null
                Message    = $null
                Attempts   = $attempt + 1
            }
        }
        catch {
            $status = Get-BowerHttpStatusCode -ErrorRecord $_
            if ($null -eq $status) {
                throw
            }

            $responseBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $null }
            if ($RetryStatusCode -contains $status -and $attempt -lt $MaximumRetryCount) {
                $delay = Get-BowerRetryDelay -ErrorRecord $_ -Attempt $attempt -MaximumSeconds $MaximumRetryDelaySeconds
                Write-Verbose ('HTTP {0}; retrying in {1:N1} s ({2} of {3} retries).' -f $status, $delay, ($attempt + 1), $MaximumRetryCount)
                Wait-BowerRetryDelay -Seconds $delay
                $attempt++
                continue
            }

            return [pscustomobject]@{
                Succeeded  = $false
                StatusCode = $status
                Content    = $null
                Body       = $responseBody
                Message    = Get-BowerApiErrorMessage -StatusCode $status -Body $responseBody
                Attempts   = $attempt + 1
            }
        }
    }
}
