function Invoke-BowerManagementRequest {
    <#
    .SYNOPSIS
    Sends a request to the connected Bower management API.

    .DESCRIPTION
    Low-level access to any /api endpoint with the session token, for endpoints without a
    dedicated cmdlet. -Path is relative to /api. Bodies are serialised as JSON. Errors
    surface the API's `error` message. The API enforces every permission; this command
    adds no privileges. Prefer the dedicated cmdlets for state changes, because they
    support -WhatIf and -Confirm.

    .PARAMETER Method
    GET (default) or POST.

    .PARAMETER Path
    Path relative to /api, for example /overview.

    .PARAMETER Body
    Request body (object serialised to JSON, or a JSON string).

    .EXAMPLE
    Invoke-BowerManagementRequest -Path /overview

    Returns the fleet overview.

    .EXAMPLE
    Invoke-BowerManagementRequest -Method POST -Path /privacy-profiles/validate -Body @{ content = Get-Content ./profile.yaml -Raw }

    Validates a privacy profile on the server.
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
        [object] $Body
    )

    try {
        Invoke-BowerManagementApi -Method $Method -Path $Path -Body $Body
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
