function Approve-BowerCollector {
    <#
    .SYNOPSIS
    Approves a pending collector enrolment.

    .DESCRIPTION
    Approves a Pending collector so its next identity-bound heartbeat makes it Active. The reason, your object ID and display name are recorded in the same transaction as the state change and audit row.

    Requires the Bower.Approver app role (enforced by the API). Calls POST /api/approvals/{id}/approve.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name (Id or CollectorId).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Get-BowerCollector -Status Pending | Approve-BowerCollector -Reason 'Inventory CHG-1042 verified'

    Approves every pending collector after inventory review (prompts are shown when $ConfirmPreference is Medium or lower).

    .EXAMPLE
    Approve-BowerCollector -Id web-07 -Reason 'Change CHG-1' -WhatIf

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
            if ($PSCmdlet.ShouldProcess("collector '$Id'", 'Approve')) {
                Invoke-BowerManagementApi -Method POST -Path "/approvals/$(ConvertTo-BowerPathSegment -Value $Id)/approve" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.ApprovalRecord'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
