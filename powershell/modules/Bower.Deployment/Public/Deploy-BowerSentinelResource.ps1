function Deploy-BowerSentinelResource {
    <#
    .SYNOPSIS
    Plans (default) or applies the Bower Sentinel resources from deploy/bicep/main.bicep.

    .DESCRIPTION
    Wraps `az deployment group what-if` (default) and `az deployment group create`
    (-Apply) for the BowerSecurity_CL table, data collection endpoint and rule, and the
    Monitoring Metrics Publisher assignment scoped to that rule. Inputs are validated the
    same way as deploy/entra/plan_ingestion.py: exactly one of -IngestPrincipalObjectId or
    -CreateIngestIdentity, Azure region identifiers, and exact HTTPS federation issuer and
    subject (new identity only, no wildcards).

    The returned plan lists the exact az command, the template and parameter SHA-256
    hashes, and the what-if result. -WhatIf runs nothing. -Apply deploys only after
    ShouldProcess confirmation (ConfirmImpact High). No credentials are created.

    .PARAMETER ResourceGroupName
    Resource group containing the Log Analytics workspace.

    .PARAMETER WorkspaceName
    Existing Log Analytics workspace name.

    .PARAMETER Location
    Azure region identifier, for example australiaeast. Defaults to the resource group location.

    .PARAMETER NamePrefix
    Resource name prefix (3-40 letters, digits or hyphens). Default bower.

    .PARAMETER IngestPrincipalObjectId
    Existing service principal object ID to receive ingestion rights on the DCR.

    .PARAMETER CreateIngestIdentity
    Create a user-assigned managed identity for ingestion instead.

    .PARAMETER FederationIssuer
    Exact HTTPS OIDC issuer for workload identity federation (with -CreateIngestIdentity).

    .PARAMETER FederationSubject
    Exact OIDC subject for federation.

    .PARAMETER PublicNetworkAccess
    Enabled (default) or Disabled for the data collection endpoint.

    .PARAMETER PrivateLinkScopeName
    Optional new Azure Monitor Private Link Scope (1-80 letters, digits, hyphens, periods or
    underscores). The data collection endpoint and workspace join it, so relays reach the
    Logs Ingestion API over Private Link. Pair with -PublicNetworkAccess Disabled.

    .PARAMETER PrivateEndpointSubnetId
    Optional subnet resource ID for the scope's private endpoint (requires -PrivateLinkScopeName).

    .PARAMETER SubscriptionId
    Subscription to target. Defaults to the az CLI's current subscription.

    .PARAMETER DeploymentName
    Deployment name. Default bower-sentinel.

    .PARAMETER TemplatePath
    Bicep template path. Defaults to deploy/bicep/main.bicep in this repository.

    .PARAMETER AzPath
    Path to the az executable. Defaults to az on PATH.

    .PARAMETER Apply
    Deploy instead of planning. Requires confirmation.

    .EXAMPLE
    Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity

    Runs az what-if and returns the plan with hashes. Nothing is changed.

    .EXAMPLE
    Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel `
        -IngestPrincipalObjectId 4c1f3a2e-9b7d-4e6f-8a5c-1d2e3f4a5b6c -Apply

    Deploys after confirmation, granting an existing principal ingestion on the DCR only.

    .EXAMPLE
    Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity `
        -PublicNetworkAccess Disabled -PrivateLinkScopeName ampls-bower `
        -PrivateEndpointSubnetId /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-dmz/subnets/relay

    Plans a private-only data collection endpoint behind a new Private Link scope with an endpoint in the relay subnet.

    .OUTPUTS
    Bower.DeploymentPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'ExistingPrincipal')]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[-\w\._\(\)]{1,90}$')]
        [string] $ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{2,62}$' }, ErrorMessage = 'Workspace name must contain 3-63 letters, digits or hyphens.')]
        [string] $WorkspaceName,

        [ValidateScript({ $_ -cmatch '^[a-z][a-z0-9]{1,39}$' }, ErrorMessage = 'Use an Azure region identifier, such as australiaeast.')]
        [string] $Location,

        [ValidateScript({ $_ -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{2,39}$' }, ErrorMessage = 'Name prefix must contain 3-40 letters, digits or hyphens.')]
        [string] $NamePrefix = 'bower',

        [Parameter(Mandatory, ParameterSetName = 'ExistingPrincipal')]
        [ValidateScript({ $_ -ne [guid]::Empty }, ErrorMessage = 'Principal object ID must not be the zero GUID.')]
        [guid] $IngestPrincipalObjectId,

        [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')]
        [switch] $CreateIngestIdentity,

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [ValidateLength(1, 600)]
        [string] $FederationIssuer,

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [ValidateLength(1, 600)]
        [string] $FederationSubject,

        [ValidateSet('Enabled', 'Disabled')]
        [string] $PublicNetworkAccess = 'Enabled',

        [ValidateScript({ $_ -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' }, ErrorMessage = 'Private Link scope name must contain 1-80 letters, digits, periods, hyphens or underscores.')]
        [string] $PrivateLinkScopeName,

        [ValidateScript({ $_ -cmatch '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[-\w\._\(\)]{1,90}/providers/Microsoft\.Network/virtualNetworks/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/subnets/[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' }, ErrorMessage = 'Private endpoint subnet must be a full subnet resource ID.')]
        [string] $PrivateEndpointSubnetId,

        [guid] $SubscriptionId,

        [ValidatePattern('^[-\w\.\(\)]{1,64}$')]
        [string] $DeploymentName = 'bower-sentinel',

        [string] $TemplatePath,

        [string] $AzPath,

        [switch] $Apply
    )

    try {
        if ([bool]$FederationIssuer -ne [bool]$FederationSubject) {
            throw [System.ArgumentException]::new('Federation requires both exact issuer and subject.')
        }
        if ($FederationIssuer) {
            $issuer = [uri]$FederationIssuer
            if (-not $issuer.IsAbsoluteUri -or $issuer.Scheme -ne 'https' -or $issuer.UserInfo -or $issuer.Query -or $issuer.Fragment -or
                $FederationIssuer -match '[\s*]' -or $FederationSubject -match '[\s*]' -or $FederationSubject -match '[\x00-\x1F]') {
                throw [System.ArgumentException]::new('Federation needs a new identity, HTTPS issuer and bounded exact subject.')
            }
        }

        if ($PrivateEndpointSubnetId -and -not $PrivateLinkScopeName) {
            throw [System.ArgumentException]::new('A private endpoint subnet requires -PrivateLinkScopeName.')
        }

        $template = Resolve-BowerTemplatePath -Path $TemplatePath -Default 'deploy/bicep/main.bicep'
        $parameters = [ordered]@{ workspaceName = $WorkspaceName; namePrefix = $NamePrefix }
        if ($Location) { $parameters.location = $Location }
        if ($CreateIngestIdentity) {
            $parameters.createIngestIdentity = $true
            if ($FederationIssuer) {
                $parameters.federationIssuer = $FederationIssuer
                $parameters.federationSubject = $FederationSubject
            }
        }
        else {
            $parameters.ingestPrincipalObjectId = $IngestPrincipalObjectId.ToString()
        }
        $parameters.publicNetworkAccess = $PublicNetworkAccess
        if ($PrivateLinkScopeName) {
            $parameters.privateLinkScopeName = $PrivateLinkScopeName
            if ($PrivateEndpointSubnetId) { $parameters.privateEndpointSubnetId = $PrivateEndpointSubnetId }
        }

        $target = "resource group '$ResourceGroupName' (workspace '$WorkspaceName')"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, 'Deploy Bower Sentinel resources (az deployment group create)')) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Plan Bower Sentinel resources (az deployment group what-if)')
            'Preview'
        }
        else {
            'Plan'
        }

        Invoke-BowerAzDeployment -Name 'sentinel' -TemplatePath $template -ResourceGroupName $ResourceGroupName `
            -SubscriptionId $(if ($PSBoundParameters.ContainsKey('SubscriptionId')) { $SubscriptionId.ToString() }) `
            -DeploymentName $DeploymentName -Parameters $parameters -Mode $mode -AzPath $AzPath -RemainingChecks @(
            'Review the what-if output in the intended tenant and subscription before -Apply.',
            'Attach the ingestion identity to collector compute; never use client secrets.',
            'Query a canary in the workspace with a separate reader identity; upload acceptance is not destination proof.'
        )
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
