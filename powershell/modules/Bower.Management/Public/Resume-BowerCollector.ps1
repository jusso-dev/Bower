function Resume-BowerCollector {
    <#
    .SYNOPSIS
    Reinstates a suspended collector.

    .DESCRIPTION
    Reinstates a suspended collector (POST /api/collectors/{id}/reinstate), returning it to Approved until its next heartbeat.

    Requires the Bower.Administrator app role (enforced by the API). Calls POST /api/collectors/{id}/reinstate.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name (Id or CollectorId).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Resume-BowerCollector -Id web-07 -Reason 'Investigation INC-311 closed'

    Reinstates a collector after an investigation.

    .EXAMPLE
    Resume-BowerCollector -Id web-07 -Reason 'Change CHG-1' -WhatIf

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
            if ($PSCmdlet.ShouldProcess("collector '$Id'", 'Reinstate')) {
                Invoke-BowerManagementApi -Method POST -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $Id)/reinstate" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.ApprovalRecord'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
