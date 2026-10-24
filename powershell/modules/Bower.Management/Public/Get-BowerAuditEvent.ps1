function Get-BowerAuditEvent {
    <#
    .SYNOPSIS
    Lists management audit events.

    .DESCRIPTION
    Calls GET /api/audit and returns audit rows (action, target, actor and time), newest
    first as returned by the API. -Action, -TargetType and -TargetId filter the returned
    rows locally and accept wildcards. Requires the Bower.Viewer app role or higher.

    .PARAMETER Action
    Audit action filter, for example collector.revoked or privacy-profile.*.

    .PARAMETER TargetType
    Target type filter, for example collector or privacy-profile-version.

    .PARAMETER TargetId
    Target ID filter.

    .EXAMPLE
    Get-BowerAuditEvent -Action 'privacy-profile.*'

    Lists privacy profile submissions and review decisions.

    .EXAMPLE
    Get-BowerAuditEvent -TargetType collector -TargetId web-07

    Shows every management action taken on one collector.

    .OUTPUTS
    Bower.AuditEvent
    #>
    [CmdletBinding()]
    [OutputType('Bower.AuditEvent')]
    param(
        [SupportsWildcards()]
        [string] $Action = '*',

        [SupportsWildcards()]
        [string] $TargetType = '*',

        [SupportsWildcards()]
        [string] $TargetId = '*'
    )

    try {
        Invoke-BowerManagementApi -Path '/audit' |
            Where-Object { $_.action -like $Action -and $_.targetType -like $TargetType -and $_.targetId -like $TargetId } |
            Add-BowerTypeName -TypeName 'Bower.AuditEvent'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
