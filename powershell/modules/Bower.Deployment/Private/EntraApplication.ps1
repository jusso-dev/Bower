function Invoke-BowerGraphCommand {
    <#
    Runs one Microsoft Graph PowerShell command by name with splatted parameters. Kept
    separate so tests can mock it; the module never calls Graph any other way.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Get-MgContext', 'New-MgApplication', 'Update-MgApplication', 'New-MgServicePrincipal')]
        [string] $Name,

        [hashtable] $Parameters = @{}
    )

    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        $module = if ($Name -eq 'Get-MgContext') { 'Microsoft.Graph.Authentication' } else { 'Microsoft.Graph.Applications' }
        Import-Module -Name $module -ErrorAction SilentlyContinue -Verbose:$false
        $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    }
    if (-not $command) {
        throw [System.InvalidOperationException]::new(
            "$Name is not available. Install Microsoft.Graph.Applications (Install-Module Microsoft.Graph.Applications -Scope CurrentUser) and run Connect-MgGraph -Scopes Application.ReadWrite.All.")
    }
    & $command @Parameters -ErrorAction Stop
}

function Read-BowerEntraManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $manifest = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    foreach ($forbidden in 'passwordCredentials', 'keyCredentials') {
        if ($manifest.ContainsKey($forbidden) -and @($manifest[$forbidden]).Count -gt 0) {
            throw [System.InvalidOperationException]::new("Manifest '$Path' contains $forbidden; Bower app registrations never carry client secrets or certificates.")
        }
    }
    if ($manifest['signInAudience'] -ne 'AzureADMyOrg') {
        throw [System.InvalidOperationException]::new("Manifest '$Path' must be single-tenant (signInAudience AzureADMyOrg).")
    }
    $manifest
}
