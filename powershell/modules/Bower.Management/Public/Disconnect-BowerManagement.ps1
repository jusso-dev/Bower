function Disconnect-BowerManagement {
    <#
    .SYNOPSIS
    Discards the Bower management connection and its in-memory token.

    .DESCRIPTION
    Clears the module-scoped endpoint, token and token provider. Nothing is stored on disk,
    so nothing else needs cleaning up. Az.Accounts sign-in state is not changed.

    .EXAMPLE
    Disconnect-BowerManagement

    Forgets the current connection.

    .EXAMPLE
    try { Get-BowerCollector } finally { Disconnect-BowerManagement }

    Ensures the token is discarded after a script finishes.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    if ($script:BowerManagementConnection) {
        $script:BowerManagementConnection.Auth = $null
        $script:BowerManagementConnection.TokenProvider = $null
    }
    $script:BowerManagementConnection = $null
    Write-Verbose 'Disconnected from Bower management.'
}
