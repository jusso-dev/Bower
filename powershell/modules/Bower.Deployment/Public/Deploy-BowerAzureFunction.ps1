function Deploy-BowerAzureFunction {
    <#
    .SYNOPSIS
    Plans (default) or applies the Bower Azure Function collector from deploy/azure-function/main.bicep.

    .DESCRIPTION
    Wraps `az deployment group what-if` (default) and `az deployment group create`
    (-Apply) for the Azure Function collector that serves the /v1/events contract with
    Entra authentication and forwards to the Logs Ingestion API.

    Parameters map one-to-one to the template: location, namePrefix, dcrResourceId,
    logsIngestionEndpoint, streamName, entraTenantId, entraAudience and the optional
    userAssignedIdentityResourceId. -WhatIf runs nothing. -Apply deploys only after
    ShouldProcess confirmation (ConfirmImpact High).

    .PARAMETER ResourceGroupName
    Target resource group.

    .PARAMETER Location
    Azure region identifier, for example australiaeast.

    .PARAMETER NamePrefix
    Resource name prefix (3-40 letters, digits or hyphens). Default bower.

    .PARAMETER DcrResourceId
    Resource ID of the Bower data collection rule (from Deploy-BowerSentinelResource).

    .PARAMETER LogsIngestionEndpoint
    HTTPS logs ingestion endpoint of the data collection endpoint.

    .PARAMETER StreamName
    DCR stream name. Default Custom-BowerSecurity.

    .PARAMETER EntraTenantId
    Entra tenant ID that issues tokens for callers.

    .PARAMETER EntraAudience
    Accepted token audience (application ID URI or client ID of the Function's app registration).

    .PARAMETER UserAssignedIdentityResourceId
    Optional user-assigned managed identity resource ID for ingestion.

    .PARAMETER SubscriptionId
    Subscription to target. Defaults to the az CLI's current subscription.

    .PARAMETER DeploymentName
    Deployment name. Default bower-azure-function.

    .PARAMETER TemplatePath
    Bicep template path. Defaults to deploy/azure-function/main.bicep in this repository.

    .PARAMETER AzPath
    Path to the az executable. Defaults to az on PATH.

    .PARAMETER Apply
    Deploy instead of planning. Requires confirmation.

    .EXAMPLE
    Deploy-BowerAzureFunction -ResourceGroupName rg-bower -Location australiaeast `
        -DcrResourceId /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-sentinel/providers/Microsoft.Insights/dataCollectionRules/bower-dcr `
        -LogsIngestionEndpoint https://bower-dce.australiaeast-1.ingest.monitor.azure.com `
        -EntraTenantId 11111111-2222-3333-4444-555555555555 -EntraAudience api://bower-function

    Returns the what-if plan. Nothing is changed.

    .EXAMPLE
    Deploy-BowerAzureFunction @functionParameters -Apply -Confirm:$false

    Deploys a reviewed configuration without prompting (for approved automation).

    .OUTPUTS
    Bower.DeploymentPlan
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.DeploymentPlan')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[-\w\._\(\)]{1,90}$')]
        [string] $ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -cmatch '^[a-z][a-z0-9]{1,39}$' }, ErrorMessage = 'Use an Azure region identifier, such as australiaeast.')]
        [string] $Location,

        [ValidateScript({ $_ -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{2,39}$' }, ErrorMessage = 'Name prefix must contain 3-40 letters, digits or hyphens.')]
        [string] $NamePrefix = 'bower',

        [Parameter(Mandatory)]
        [ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Insights/dataCollectionRules/[^/]+$')]
        [string] $DcrResourceId,

        [Parameter(Mandatory)]
        [ValidateScript({ ([uri]$_).IsAbsoluteUri -and ([uri]$_).Scheme -eq 'https' -and -not ([uri]$_).UserInfo }, ErrorMessage = 'Logs ingestion endpoint must be an https URI.')]
        [string] $LogsIngestionEndpoint,

        [ValidatePattern('^Custom-[A-Za-z0-9_]{1,100}$')]
        [string] $StreamName = 'Custom-BowerSecurity',

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -ne [guid]::Empty }, ErrorMessage = 'Tenant ID must not be the zero GUID.')]
        [guid] $EntraTenantId,

        [Parameter(Mandatory)]
        [ValidateLength(1, 256)]
        [string] $EntraAudience,

        [ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/]+$')]
        [string] $UserAssignedIdentityResourceId,

        [guid] $SubscriptionId,

        [ValidatePattern('^[-\w\.\(\)]{1,64}$')]
        [string] $DeploymentName = 'bower-azure-function',

        [string] $TemplatePath,

        [string] $AzPath,

        [switch] $Apply
    )

    try {
        $template = Resolve-BowerTemplatePath -Path $TemplatePath -Default 'deploy/azure-function/main.bicep'
        $parameters = [ordered]@{
            location              = $Location
            namePrefix            = $NamePrefix
            dcrResourceId         = $DcrResourceId
            logsIngestionEndpoint = $LogsIngestionEndpoint
            streamName            = $StreamName
            entraTenantId         = $EntraTenantId.ToString()
            entraAudience         = $EntraAudience
        }
        if ($UserAssignedIdentityResourceId) {
            $parameters.userAssignedIdentityResourceId = $UserAssignedIdentityResourceId
        }

        $target = "resource group '$ResourceGroupName' (Azure Function '$NamePrefix')"
        $mode = if ($Apply) {
            if ($PSCmdlet.ShouldProcess($target, 'Deploy Bower Azure Function (az deployment group create)')) { 'Apply' } else { 'Preview' }
        }
        elseif ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($target, 'Plan Bower Azure Function (az deployment group what-if)')
            'Preview'
        }
        else {
            'Plan'
        }

        Invoke-BowerAzDeployment -Name 'azure-function' -TemplatePath $template -ResourceGroupName $ResourceGroupName `
            -SubscriptionId $(if ($PSBoundParameters.ContainsKey('SubscriptionId')) { $SubscriptionId.ToString() }) `
            -DeploymentName $DeploymentName -Parameters $parameters -Mode $mode -AzPath $AzPath -RemainingChecks @(
            'Review the what-if output before -Apply.',
            'Grant callers an Entra app role or token for the Function audience; never use function keys in URLs.',
            'Send a canary with Send-BowerSecurityEvent -Target AzureFunction and verify it in the workspace.'
        )
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
