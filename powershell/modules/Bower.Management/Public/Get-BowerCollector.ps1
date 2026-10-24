function Get-BowerCollector {
    <#
    .SYNOPSIS
    Lists Bower collectors, or gets one collector.

    .DESCRIPTION
    Calls GET /api/collectors (optionally filtered by status) or GET /api/collectors/{id}.
    Records are metadata only: identity, health, queue depth, policy and privacy profile
    hashes. Requires the Bower.Viewer app role or higher.

    .PARAMETER Id
    Collector ID. Accepts pipeline input by property name.

    .PARAMETER Status
    Pending, Approved, Active, Suspended or Revoked.

    .EXAMPLE
    Get-BowerCollector -Status Pending

    Lists collectors waiting for enrolment approval.

    .EXAMPLE
    Get-BowerCollector -Id web-07 | Select-Object id, status, desiredPrivacyProfile, privacyProfileInSync

    Shows a collector's privacy profile assignment and sync state.

    .OUTPUTS
    Bower.Collector
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    [OutputType('Bower.Collector')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Id', ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('CollectorId')]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(ParameterSetName = 'List')]
        [ValidateSet('Pending', 'Approved', 'Active', 'Suspended', 'Revoked')]
        [string] $Status
    )

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Id') {
                Invoke-BowerManagementApi -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $Id)" |
                    Add-BowerTypeName -TypeName 'Bower.Collector'
            }
            else {
                $query = if ($Status) { @{ status = $Status } } else { $null }
                Invoke-BowerManagementApi -Path '/collectors' -Query $query |
                    Add-BowerTypeName -TypeName 'Bower.Collector'
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
