# Module-scoped connection state. The access token lives only here, as a SecureString,
# for the lifetime of the session (or until Disconnect-BowerManagement). It is never
# written to disk, returned from a command, or included in verbose/debug output.
$script:BowerManagementConnection = $null

function Get-BowerManagementAccessToken {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Connection
    )

    if (-not (Test-BowerTokenFresh -Token $Connection.Auth)) {
        switch ($Connection.AuthenticationMethod) {
            'AzAccounts' {
                $Connection.Auth = Get-BowerAzAccessToken -ResourceUrl $Connection.Audience -TenantId $Connection.TenantId
            }
            'TokenProvider' {
                $Connection.Auth = Invoke-BowerTokenProvider -TokenProvider $Connection.TokenProvider
            }
            default {
                throw [System.InvalidOperationException]::new('The Bower management access token has expired. Run Connect-BowerManagement again.')
            }
        }
    }
    $Connection.Auth.Token
}

function ConvertTo-BowerPathSegment {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Value
    )

    [uri]::EscapeDataString($Value)
}

function Get-BowerManagementErrorCategory {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorCategory])]
    param(
        [Parameter(Mandatory)]
        [int] $StatusCode
    )

    switch ($StatusCode) {
        400 { 'InvalidArgument' }
        401 { 'AuthenticationError' }
        403 { 'PermissionDenied' }
        404 { 'ObjectNotFound' }
        409 { 'ResourceExists' }
        default { 'InvalidOperation' }
    }
}

function Invoke-BowerManagementApi {
    <#
    Calls the management API relative to /api with the session token. Returns the parsed
    response body; throws an ErrorRecord whose message carries the API `error` text.
    GET requests retry on 429/503; POST requests retry on 429 only, because a 503 may
    arrive after the server acted.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [ValidateSet('GET', 'POST')]
        [string] $Method = 'GET',

        [Parameter(Mandatory)]
        [ValidatePattern('^/[A-Za-z0-9._~%/-]*$')]
        [string] $Path,

        [AllowNull()]
        [object] $Body,

        [System.Collections.IDictionary] $Query,

        [ValidateRange(0, 10)]
        [int] $MaximumRetryCount = 3,

        [ValidateRange(1, 300)]
        [int] $MaximumRetryDelaySeconds = 30
    )

    $connection = $script:BowerManagementConnection
    if ($null -eq $connection) {
        throw [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('Not connected to Bower management. Run Connect-BowerManagement first.'),
            'BowerManagementNotConnected', 'ConnectionError', $null)
    }
    if ($Path -match '(^|/)\.\.?(/|$)') {
        throw [System.ArgumentException]::new('Path must not contain dot segments.')
    }

    $builder = [System.UriBuilder]::new($connection.Endpoint)
    $builder.Path = ($builder.Path.TrimEnd('/') + '/api' + $Path)
    if ($Query -and $Query.Count -gt 0) {
        $builder.Query = (@(foreach ($key in $Query.Keys) {
                    '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$Query[$key])
                }) -join '&')
    }
    $uri = $builder.Uri

    $request = @{
        Method                   = $Method
        Uri                      = $uri
        Token                    = Get-BowerManagementAccessToken -Connection $connection
        MaximumRetryCount        = $MaximumRetryCount
        MaximumRetryDelaySeconds = $MaximumRetryDelaySeconds
        RetryStatusCode          = if ($Method -eq 'GET') { @(429, 503) } else { @(429) }
    }
    if ($null -ne $Body) {
        $request.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 16 -Compress }
    }

    $response = Invoke-BowerHttpRequest @request
    if ($response.Succeeded) {
        return $response.Content
    }

    $status = [int]$response.StatusCode
    $hint = switch ($status) {
        401 { ' Run Connect-BowerManagement again.' }
        403 { ' Your Bower app role does not allow this operation.' }
        default { '' }
    }
    throw [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new("Bower management API $Method /api$Path failed: $($response.Message)$hint"),
        "BowerManagementApi$status",
        (Get-BowerManagementErrorCategory -StatusCode $status),
        "/api$Path")
}

function Add-BowerTypeName {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $TypeName
    )

    process {
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $InputObject.PSObject.TypeNames.Insert(0, $TypeName)
        }
        $InputObject
    }
}

function Assert-BowerReason {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Reason,

        [string] $Name = 'Reason'
    )

    if ([string]::IsNullOrWhiteSpace($Reason) -or $Reason.Trim().Length -gt 500) {
        throw [System.ArgumentException]::new("$Name must be 1-500 characters.")
    }
}

function Read-BowerProfileContent {
    <# Reads a privacy profile from -Path or -Content (exactly one), as UTF-8 text. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Path,

        [string] $Content
    )

    if ($Path -and $Content) {
        throw [System.ArgumentException]::new('Use -Path or -Content, not both.')
    }
    if ($Path) {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        return [System.IO.File]::ReadAllText($resolved.ProviderPath, [System.Text.Encoding]::UTF8)
    }
    if ([string]::IsNullOrWhiteSpace($Content)) {
        throw [System.ArgumentException]::new('Privacy profile content is required (-Path or -Content).')
    }
    $Content
}
