function Get-BowerPrivacyProfileAssignment {
    <#
    .SYNOPSIS
    Lists privacy profile assignment history.

    .DESCRIPTION
    Calls GET /api/privacy-profiles/assignments (newest first, at most 250 rows) and
    filters locally by -CollectorId and -VersionId. Each row records whether a version was
    assigned or cleared, by whom, why and when. Requires the Bower.Viewer app role or
    higher.

    .PARAMETER CollectorId
    Collector ID filter (wildcards allowed).

    .PARAMETER VersionId
    Version ID filter.

    .EXAMPLE
    Get-BowerPrivacyProfileAssignment -CollectorId web-07

    Shows the assignment history of one collector.

    .EXAMPLE
    Get-BowerPrivacyProfileAssignment | Where-Object action -eq 'cleared'

    Lists every cleared assignment.

    .OUTPUTS
    Bower.PrivacyProfileAssignment
    #>
    [CmdletBinding()]
    [OutputType('Bower.PrivacyProfileAssignment')]
    param(
        [SupportsWildcards()]
        [string] $CollectorId = '*',

        [ValidatePattern('^[0-9a-f]{32}$')]
        [string] $VersionId
    )

    try {
        Invoke-BowerManagementApi -Path '/privacy-profiles/assignments' |
            Where-Object { $_.collectorId -like $CollectorId -and (-not $VersionId -or $_.versionId -eq $VersionId) } |
            Add-BowerTypeName -TypeName 'Bower.PrivacyProfileAssignment'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
