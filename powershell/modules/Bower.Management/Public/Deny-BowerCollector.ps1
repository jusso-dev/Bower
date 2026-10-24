function Deny-BowerCollector {
    <#
    .SYNOPSIS
    Rejects a pending collector enrolment.

    .DESCRIPTION
    Rejects a Pending collector (the API records it as revoked with the action "rejected"). The reason is recorded with your identity in the management audit.

    Requires the Bower.Approver app role (enforced by the API). Calls POST /api/approvals/{id}/reject.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name (Id or CollectorId).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Deny-BowerCollector -Id web-07 -Reason 'Unknown host; not in CMDB'

    Rejects an unexpected enrolment.

    .EXAMPLE
    Deny-BowerCollector -Id web-07 -Reason 'Change CHG-1' -WhatIf

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
            if ($PSCmdlet.ShouldProcess("collector '$Id'", 'Reject enrolment')) {
                Invoke-BowerManagementApi -Method POST -Path "/approvals/$(ConvertTo-BowerPathSegment -Value $Id)/reject" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.ApprovalRecord'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
