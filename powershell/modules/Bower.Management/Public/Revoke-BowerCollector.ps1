function Revoke-BowerCollector {
    <#
    .SYNOPSIS
    Revokes a collector.

    .DESCRIPTION
    Revokes a collector permanently. Revoked collectors cannot heartbeat, re-register under the same identity or receive privacy profile assignments. ConfirmImpact is High, so PowerShell prompts unless -Confirm:$false is passed.

    Requires the Bower.Administrator app role (enforced by the API). Calls POST /api/collectors/{id}/revoke.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name (Id or CollectorId).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Revoke-BowerCollector -Id web-07 -Reason 'Host decommissioned CHG-2201'

    Revokes a decommissioned collector after confirmation.

    .EXAMPLE
    Revoke-BowerCollector -Id web-07 -Reason 'Change CHG-1' -WhatIf

    Shows what would happen without calling the API.

    .OUTPUTS
    Bower.ApprovalRecord
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.ApprovalRecord')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('CollectorId')]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Reason
    )

    process {
        try {
            Assert-BowerReason -Reason $Reason
            if ($PSCmdlet.ShouldProcess("collector '$Id'", 'Revoke')) {
                Invoke-BowerManagementApi -Method POST -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $Id)/revoke" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.ApprovalRecord'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
