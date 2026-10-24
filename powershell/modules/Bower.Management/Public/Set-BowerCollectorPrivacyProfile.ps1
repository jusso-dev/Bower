function Set-BowerCollectorPrivacyProfile {
    <#
    .SYNOPSIS
    Assigns an approved privacy profile version to a collector.

    .DESCRIPTION
    Calls POST /api/collectors/{id}/privacy-profile with the version ID and reason. Only
    Approved versions can be assigned, and revoked collectors cannot be assigned (HTTP
    409). A collector in managed privacy mode downloads the signed profile, verifies it
    and restarts to apply it; until then Get-BowerCollector shows privacyProfileInSync as
    $false. ConfirmImpact is High because the assignment changes what the collector
    redacts. Requires the Bower.Administrator app role.

    .PARAMETER CollectorId
    Collector ID. Accepts pipeline input by property name (CollectorId or Id).

    .PARAMETER VersionId
    Approved privacy profile version ID.

    .PARAMETER Reason
    Audit reason, 1-500 characters.

    .EXAMPLE
    Set-BowerCollectorPrivacyProfile -CollectorId web-07 -VersionId 3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6 -Reason 'Roll out PRIV-77'

    Assigns a version to one collector after confirmation.

    .EXAMPLE
    Get-BowerCollector -Status Active | Set-BowerCollectorPrivacyProfile -VersionId 3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6 -Reason 'Fleet rollout PRIV-77' -WhatIf

    Shows which active collectors would be assigned.

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
        [ValidatePattern('^[0-9a-f]{32}$')]
        [string] $VersionId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Reason
    )

    process {
        try {
            Assert-BowerReason -Reason $Reason
            if ($PSCmdlet.ShouldProcess("collector '$CollectorId'", "Assign privacy profile version '$VersionId'")) {
                Invoke-BowerManagementApi -Method POST -Path "/collectors/$(ConvertTo-BowerPathSegment -Value $CollectorId)/privacy-profile" `
                    -Body @{ versionId = $VersionId; reason = $Reason } |
                    Add-BowerTypeName -TypeName 'Bower.Collector'
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}
