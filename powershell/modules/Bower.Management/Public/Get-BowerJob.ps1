function Get-BowerJob {
    <#
    .SYNOPSIS
    Lists management API background jobs.

    .DESCRIPTION
    Calls GET /api/jobs and returns each recurring maintenance job with its schedule and
    last run state. -Id filters locally and accepts wildcards. Requires the Bower.Viewer
    app role or higher.

    .PARAMETER Id
    Job ID filter, for example collector-staleness.

    .EXAMPLE
    Get-BowerJob

    Lists every background job.

    .EXAMPLE
    Get-BowerJob -Id 'collector-*' | Format-List

    Shows the collector maintenance jobs in detail.

    .OUTPUTS
    Bower.Job
    #>
    [CmdletBinding()]
    [OutputType('Bower.Job')]
    param(
        [SupportsWildcards()]
        [string] $Id = '*'
    )

    try {
        Invoke-BowerManagementApi -Path '/jobs' |
            Where-Object { $_.id -like $Id } |
            Add-BowerTypeName -TypeName 'Bower.Job'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
