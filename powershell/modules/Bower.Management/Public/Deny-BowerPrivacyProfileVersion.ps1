function Deny-BowerPrivacyProfileVersion {
    <#
    .SYNOPSIS
    Rejects a privacy profile version that is pending review.

    .DESCRIPTION
    Records a review decision for a PendingReview privacy profile version
    (POST /api/privacy-profiles/versions/{id}/reject). The API enforces the two-person
    rule: the author of a version cannot review it (HTTP 409), and only PendingReview
    versions can be decided (HTTP 409). Requires the Bower.Approver or
    Bower.Administrator app role.

    .PARAMETER Id
    Privacy profile version ID (32 lowercase hex characters). Accepts pipeline input by
    property name.

    .PARAMETER Reason
    Review reason, 1-500 characters, recorded in the management audit.

    .EXAMPLE
    Deny-BowerPrivacyProfileVersion -Id 3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6 -Reason 'Custom detector pattern too broad'

    Rejects versions after review.

    .EXAMPLE
    Deny-BowerPrivacyProfileVersion -Id 3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6 -Reason 'Reviewed' -WhatIf

    Shows what would happen without calling the API.

    .OUTPUTS
    Bower.PrivacyProfileVersion
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType('Bower.PrivacyProfileVersion')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('VersionId')]
        [ValidatePattern('^[0-9a-f]{32}$')]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Reason
    )

    process {
        try {
            Assert-BowerReason -Reason $Reason
            if ($PSCmdlet.ShouldProcess("privacy profile version '$Id'", 'Reject')) {
                Invoke-BowerManagementApi -Method POST -Path "/privacy-profiles/versions/$Id/reject" -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.PrivacyProfileVersion'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
