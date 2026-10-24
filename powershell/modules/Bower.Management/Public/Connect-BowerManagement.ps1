function Connect-BowerManagement {
    <#
    .SYNOPSIS
    Connects the session to a Bower management API.

    .DESCRIPTION
    Stores the endpoint and an Entra access token in module-scoped memory and verifies
    them with GET /api/access/me. The token is kept as a SecureString, is never written
    to disk, and is never returned or logged. It is discarded by Disconnect-BowerManagement
    or when the PowerShell session ends.

    Token sources (choose one):
    - Az.Accounts (default): Get-AzAccessToken -ResourceUrl <Audience>. Run Connect-AzAccount
      first. Tokens are re-acquired automatically shortly before they expire. The Azure
      PowerShell client must be allowed to request tokens for the API (pre-authorise it on
      the Bower Management API app registration, or use -TokenProvider with MSAL).
    - -AccessToken: a SecureString access token you already hold. It is not refreshed.
    - -TokenProvider: a script block that returns a SecureString (or an object with Token
      and ExpiresOn); it is called again when the token is about to expire.

    Remote endpoints must use https; plain http is accepted only for loopback hosts.

    .PARAMETER Endpoint
    Management API base URI, for example https://bower-api.example.gov.au.

    .PARAMETER Audience
    Entra resource for the API, usually api://<api-application-client-id>.

    .PARAMETER TenantId
    Entra tenant ID used by Az.Accounts.

    .PARAMETER AccessToken
    Access token as a SecureString.

    .PARAMETER TokenProvider
    Script block that returns a token.

    .EXAMPLE
    Connect-AzAccount -Tenant 11111111-2222-3333-4444-555555555555
    Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -Audience api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

    Connects with an Az.Accounts token.

    .EXAMPLE
    Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -TokenProvider { Get-Secret -Name bower-mgmt-token }

    Connects with a token from SecretManagement.

    .EXAMPLE
    Connect-BowerManagement -Endpoint http://127.0.0.1:4320 -AccessToken (Read-Host -AsSecureString)

    Connects to a local management API with a pasted token.

    .OUTPUTS
    Bower.ManagementConnection
    #>
    [CmdletBinding(DefaultParameterSetName = 'AzAccounts')]
    [OutputType('Bower.ManagementConnection')]
    param(
        [Parameter(Mandatory)]
        [uri] $Endpoint,

        [Parameter(Mandatory, ParameterSetName = 'AzAccounts')]
        [ValidateNotNullOrEmpty()]
        [string] $Audience,

        [Parameter(ParameterSetName = 'AzAccounts')]
        [ValidateNotNullOrEmpty()]
        [string] $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'AccessToken')]
        [securestring] $AccessToken,

        [Parameter(Mandatory, ParameterSetName = 'TokenProvider')]
        [scriptblock] $TokenProvider
    )

    try {
        Assert-BowerTransportUri -Uri $Endpoint -Name 'Endpoint'
        if ($Endpoint.Query -or $Endpoint.Fragment) {
            throw [System.ArgumentException]::new('Endpoint must not contain a query string or fragment.')
        }

        $connection = @{
            Endpoint             = $Endpoint
            AuthenticationMethod = $PSCmdlet.ParameterSetName
            Audience             = $Audience
            TenantId             = $TenantId
            TokenProvider        = $TokenProvider
            Auth                 = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'AccessToken' {
                $connection.Auth = Resolve-BowerToken -Result $AccessToken -Source '-AccessToken'
            }
            'TokenProvider' {
                $connection.Auth = Invoke-BowerTokenProvider -TokenProvider $TokenProvider
            }
            default {
                $connection.Auth = Get-BowerAzAccessToken -ResourceUrl $Audience -TenantId $TenantId
            }
        }

        $previous = $script:BowerManagementConnection
        $script:BowerManagementConnection = $connection
        try {
            $access = Invoke-BowerManagementApi -Method GET -Path '/access/me'
        }
        catch {
            $script:BowerManagementConnection = $previous
            throw
        }

        $connection.Principal = $access
        Get-BowerManagementConnection
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
