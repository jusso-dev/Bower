function New-BowerEntraApplication {
    <#
    .SYNOPSIS
    Plans (default) or creates the Bower Management API and Web Entra app registrations.

    .DESCRIPTION
    Uses the checked-in manifests deploy/entra/api-app-manifest.json and
    deploy/entra/spa-app-manifest.json (single-tenant, stable app role and Bower.Access
    scope IDs, no secrets). Plan mode returns the exact application bodies and steps and
    calls nothing.

    -Apply creates, after ShouldProcess confirmation (ConfirmImpact High), through
    Microsoft.Graph.Applications (connect first with
    Connect-MgGraph -Scopes Application.ReadWrite.All):
      1. the API application, then sets identifierUris to api://<appId>;
      2. its service principal (the enterprise application that receives group-to-role
         assignments);
      3. the SPA application with the given redirect URIs and delegated Bower.Access
         permission on the API;
      4. its service principal.
    No client secrets or certificates are created. Admin consent, group-to-role
    assignment and Bower.Collector assignment to collector identities remain manual
    (see docs/security/management-identity-and-rbac.md).

    .PARAMETER RedirectUri
    SPA redirect URIs (https, or http://localhost for development).

    .PARAMETER ApiDisplayName
    API application display name. Default Bower Management API.

    .PARAMETER WebDisplayName
    SPA application display name. Default Bower Management Web.

    .PARAMETER TenantId
    Expected tenant. With -Apply, the Graph connection must be in this tenant.

    .PARAMETER ManifestDirectory
    Directory containing the manifests. Defaults to deploy/entra in this repository.

    .PARAMETER Apply
    Create the registrations instead of planning. Requires confirmation.

    .EXAMPLE
    New-BowerEntraApplication -RedirectUri https://bower.example.gov.au

    Shows the registrations that would be created.

    .EXAMPLE
    Connect-MgGraph -TenantId 11111111-2222-3333-4444-555555555555 -Scopes Application.ReadWrite.All
    New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -TenantId 11111111-2222-3333-4444-555555555555 -Apply

    Creates both registrations in the connected tenant after confirmation.

    .OUTPUTS
    Bower.EntraApplicationPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.EntraApplicationPlan')]
    param(
        [Parameter(Mandatory)]
        [ValidateCount(1, 16)]
        [ValidateScript({
                $uri = [uri]$_
                $uri.IsAbsoluteUri -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment -and
                ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $uri.Host -eq 'localhost'))
            }, ErrorMessage = "Redirect URI '{0}' must be https (or http://localhost) without query or fragment.")]
        [string[]] $RedirectUri,

        [ValidateLength(1, 120)]
        [string] $ApiDisplayName = 'Bower Management API',

        [ValidateLength(1, 120)]
        [string] $WebDisplayName = 'Bower Management Web',

        [ValidateScript({ $_ -ne [guid]::Empty }, ErrorMessage = 'Tenant ID must not be the zero GUID.')]
        [guid] $TenantId,

        [string] $ManifestDirectory,

        [switch] $Apply
    )

    try {
        $directory = Resolve-BowerTemplatePath -Path $ManifestDirectory -Default 'deploy/entra'
        $apiManifestPath = Join-Path $directory 'api-app-manifest.json'
        $webManifestPath = Join-Path $directory 'spa-app-manifest.json'
        $api = Read-BowerEntraManifest -Path $apiManifestPath
        $web = Read-BowerEntraManifest -Path $webManifestPath

        $scope = @($api.api.oauth2PermissionScopes | Where-Object { $_.value -eq 'Bower.Access' }) | Select-Object -First 1
        if (-not $scope) {
            throw [System.InvalidOperationException]::new('API manifest does not expose the Bower.Access scope.')
        }

        $api.displayName = $ApiDisplayName
        $api.Remove('identifierUris')   # set to api://<appId> once the appId exists
        $web.displayName = $WebDisplayName
        $web.spa = @{ redirectUris = @($RedirectUri) }
        $web.requiredResourceAccess = @(@{
                resourceAppId  = '<api-application-client-id>'
                resourceAccess = @(@{ id = $scope.id; type = 'Scope' })
            })

        $steps = @(
            "New-MgApplication '$ApiDisplayName' (app roles: $((@($api.appRoles) | ForEach-Object { $_.value }) -join ', '); scope: Bower.Access)",
            'Update-MgApplication identifierUris = api://<api-application-client-id>',
            "New-MgServicePrincipal for '$ApiDisplayName'",
            "New-MgApplication '$WebDisplayName' (SPA redirect URIs: $($RedirectUri -join ', '); delegated Bower.Access)",
            "New-MgServicePrincipal for '$WebDisplayName'"
        )
        $remaining = @(
            "Grant tenant admin consent for the SPA's delegated Bower.Access permission.",
            'Assign Entra security groups to Bower.Viewer, Bower.Operator, Bower.Approver and Bower.Administrator on the API enterprise application.',
            'Assign Bower.Collector directly to each collector managed identity or service principal.',
            'Set Bower__Entra__TenantId and Bower__Entra__Audience (API client ID) on the management API.'
        )

        $target = "Entra tenant$(if ($TenantId) { " $TenantId" })"
        $approved = $Apply -and $PSCmdlet.ShouldProcess($target, "Create app registrations '$ApiDisplayName' and '$WebDisplayName'")
        if (-not $Apply -and $WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Plan Bower Entra app registrations')
        }
        $mode = if ($approved) { 'Apply' } elseif ($Apply -or $WhatIfPreference) { 'Preview' } else { 'Plan' }

        $result = $null
        if ($mode -eq 'Apply') {
            $context = Invoke-BowerGraphCommand -Name 'Get-MgContext'
            if (-not $context) {
                throw [System.InvalidOperationException]::new('Not connected to Microsoft Graph. Run Connect-MgGraph -Scopes Application.ReadWrite.All.')
            }
            if ($TenantId -and $context.TenantId -ne $TenantId.ToString()) {
                throw [System.InvalidOperationException]::new("Microsoft Graph is connected to tenant '$($context.TenantId)', not '$TenantId'.")
            }

            $apiApp = Invoke-BowerGraphCommand -Name 'New-MgApplication' -Parameters @{ BodyParameter = $api }
            Invoke-BowerGraphCommand -Name 'Update-MgApplication' -Parameters @{ ApplicationId = $apiApp.Id; IdentifierUris = @("api://$($apiApp.AppId)") } | Out-Null
            $apiPrincipal = Invoke-BowerGraphCommand -Name 'New-MgServicePrincipal' -Parameters @{ AppId = $apiApp.AppId }

            $web.requiredResourceAccess[0].resourceAppId = $apiApp.AppId
            $webApp = Invoke-BowerGraphCommand -Name 'New-MgApplication' -Parameters @{ BodyParameter = $web }
            $webPrincipal = Invoke-BowerGraphCommand -Name 'New-MgServicePrincipal' -Parameters @{ AppId = $webApp.AppId }

            $result = [pscustomobject]@{
                TenantId                 = $context.TenantId
                ApiApplicationId         = $apiApp.AppId
                ApiObjectId              = $apiApp.Id
                ApiServicePrincipalId    = $apiPrincipal.Id
                ApiIdentifierUri         = "api://$($apiApp.AppId)"
                ApiScope                 = "api://$($apiApp.AppId)/Bower.Access"
                WebApplicationId         = $webApp.AppId
                WebObjectId              = $webApp.Id
                WebServicePrincipalId    = $webPrincipal.Id
            }
        }

        [pscustomobject]@{
            PSTypeName        = 'Bower.EntraApplicationPlan'
            Mode              = $mode
            ApiApplication    = $api
            WebApplication    = $web
            Steps             = $steps
            Executed          = $mode -eq 'Apply'
            CredentialsCreated = $false
            Result            = $result
            RemainingChecks   = $remaining
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
