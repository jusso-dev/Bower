function Clear-BowerCollectorPrivacyProfile {
    <#
    .SYNOPSIS
    Removes a collector's privacy profile assignment.

    .DESCRIPTION
    Calls POST /api/collectors/{id}/privacy-profile/clear with a reason. A collector in
    managed privacy mode then deletes its cached profile and restarts with the built-in
    default privacy profile. ConfirmImpact is High. Requires the Bower.Administrator app
    role.

    .PARAMETER CollectorId
    Collector ID. Accepts pipeline input by property name (CollectorId or Id).

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Clear-BowerCollectorPrivacyProfile -CollectorId web-07 -Reason 'Return to default profile PRIV-80'

    Clears the assignment after confirmation.

    .EXAMPLE
    Get-BowerCollector -Id web-07 | Clear-BowerCollectorPrivacyProfile -Reason 'Rollback' -Confirm:$false

    Clears without prompting (for reviewed automation).

    .OUTPUTS
    Bower.Collector
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Bower.Collector')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [ValidateNotNullOrEmpty()]
        [string] $CollectorId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Reason
    )

    process {
        try {
            Assert-BowerReason -Reason $Reason
            if ($PSCmdlet.ShouldProcess("collector '$CollectorId'", 'Clear privacy profile assignment')) {
                Invoke-BowerManagementApi -Method POST -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $CollectorId)/privacy-profile/clear" `
                    -Body @{ reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.Collector'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
