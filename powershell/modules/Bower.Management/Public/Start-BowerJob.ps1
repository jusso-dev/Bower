function Start-BowerJob {
    <#
    .SYNOPSIS
    Triggers a management API background job now.

    .DESCRIPTION
    Calls POST /api/jobs/{id}/trigger. The API records a job.triggered audit row with your
    identity. The endpoint takes no reason, so this cmdlet has no -Reason parameter.
    Requires the Bower.Administrator app role.

    .PARAMETER Id
    Job ID. Accepts pipeline input by property name.

    .EXAMPLE
    Start-BowerJob -Id collector-staleness

    Runs the collector staleness check immediately.

    .EXAMPLE
    Get-BowerJob -Id 'collector-*' | Start-BowerJob -WhatIf

    Shows which jobs would be triggered.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Id
    )

    process {
        try {
            if ($PSCmdlet.ShouldProcess("job '$Id'", 'Trigger')) {
                $null = Invoke-BowerManagementApi -Method POST -Path "/jobs/$(ConvertTo-BowerPathSegment -Value $Id)/trigger"
                Write-Verbose "Triggered job '$Id'."
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
