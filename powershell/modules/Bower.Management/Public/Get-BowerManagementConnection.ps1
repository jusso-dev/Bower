function Get-BowerManagementConnection {
    <#
    .SYNOPSIS
    Shows the current Bower management connection (metadata only).

    .DESCRIPTION
    Returns the endpoint, authentication method, signed-in principal, app roles and token
    expiry of the current connection. The access token itself is never returned. Returns
    nothing when not connected.

    .EXAMPLE
    Get-BowerManagementConnection

    Shows who you are connected as and which Bower app roles you hold.

    .EXAMPLE
    if (-not (Get-BowerManagementConnection)) { Connect-BowerManagement -Endpoint $endpoint -Audience $audience }

    Connects only when there is no current connection.

    .OUTPUTS
    Bower.ManagementConnection
    #>
    [CmdletBinding()]
    [OutputType('Bower.ManagementConnection')]
    param()

    $connection = $script:BowerManagementConnection
    if ($null -eq $connection) {
        return
    }

    $principal = $connection.Principal
    [pscustomobject]@{
        PSTypeName                = 'Bower.ManagementConnection'
        Endpoint                  = $connection.Endpoint.GetLeftPart([System.UriPartial]::Path)
        AuthenticationMethod      = $connection.AuthenticationMethod
        Audience                  = $connection.Audience
        TenantId                  = $connection.TenantId
        ObjectId                  = if ($principal) { $principal.objectId } else { $null }
        DisplayName               = if ($principal) { $principal.displayName } else { $null }
        Roles                     = if ($principal) { @($principal.roles) } else { @() }
        DevelopmentAuthentication = if ($principal) { [bool]$principal.developmentAuthentication } else { $false }
        TokenExpiresOn            = if ($connection.Auth) { $connection.Auth.ExpiresOn } else { $null }
    }
}
