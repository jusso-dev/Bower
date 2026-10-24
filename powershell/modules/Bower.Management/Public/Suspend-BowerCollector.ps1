function Suspend-BowerCollector {
    <#
    .SYNOPSIS
    Suspends a collector.

    .DESCRIPTION
    Suspends an approved or active collector. Suspension is reversible with Resume-BowerCollector. Local collection and delivery are not stopped by the management plane.

    Requires the Bower.Administrator app role (enforced by the API). Calls POST /api/collectors/{id}/suspend.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name (Id or CollectorId).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Suspend-BowerCollector -Id web-07 -Reason 'Host under investigation INC-311'

    Suspends a collector during an investigation.

    .EXAMPLE
    Suspend-BowerCollector -Id web-07 -Reason 'Change CHG-1' -WhatIf

    Shows what would happen without calling the API.

    .OUTPUTS
    Bower.ApprovalRecord
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
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
            if ($PSCmdlet.ShouldProcess("collector '$Id'", 'Suspend')) {
                Invoke-BowerManagementApi -Method POST -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $Id)/suspend" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.ApprovalRecord'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
