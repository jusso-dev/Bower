function Get-BowerPrivacyProfileVersion {
    <#
    .SYNOPSIS
    Lists privacy profile versions, or gets one version with its content.

    .DESCRIPTION
    Without -Id, calls GET /api/privacy-profiles (newest first, at most 500 summaries) and
    filters locally by -ProfileId and -Status. With -Id, calls
    GET /api/privacy-profiles/versions/{id} and returns the detail including content,
    author object ID and previousApprovedVersionId. Requires the Bower.Viewer app role or
    higher.

    .PARAMETER Id
    Version ID (32 lowercase hex characters). Accepts pipeline input by property name.

    .PARAMETER ProfileId
    metadata.id filter (wildcards allowed).

    .PARAMETER Status
    PendingReview, Approved or Rejected.

    .EXAMPLE
    Get-BowerPrivacyProfileVersion -Status PendingReview

    Lists versions waiting for review.

    .EXAMPLE
    Get-BowerPrivacyProfileVersion -ProfileId contoso-app -Status Approved | Select-Object -First 1 | Get-BowerPrivacyProfileVersion

    Gets the content of the latest approved version of a profile.

    .OUTPUTS
    Bower.PrivacyProfileVersion
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    [OutputType('Bower.PrivacyProfileVersion')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Id', ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('VersionId')]
        [ValidatePattern('^[0-9a-f]{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = 'List')]
        [SupportsWildcards()]
        [string] $ProfileId = '*',

        [Parameter(ParameterSetName = 'List')]
        [ValidateSet('PendingReview', 'Approved', 'Rejected')]
        [string] $Status
    )

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Id') {
                Invoke-BowerManagementApi -Path "/privacy-profiles/versions/$Id" |
                    Add-BowerTypeName -TypeName 'Bower.PrivacyProfileVersion'
            }
            else {
                Invoke-BowerManagementApi -Path '/privacy-profiles' |
                    Where-Object { $_.profileId -like $ProfileId -and (-not $Status -or $_.status -eq $Status) } |
                    Add-BowerTypeName -TypeName 'Bower.PrivacyProfileVersion'
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
