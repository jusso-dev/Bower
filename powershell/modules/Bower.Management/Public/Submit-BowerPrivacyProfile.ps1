function Submit-BowerPrivacyProfile {
    <#
    .SYNOPSIS
    Submits a privacy profile version for review.

    .DESCRIPTION
    Calls POST /api/privacy-profiles with the profile YAML and a change summary. The API
    validates the profile, requires metadata.version to be MAJOR.MINOR.PATCH and greater
    than every existing version of the same metadata.id, and stores an immutable
    PendingReview version. Another person must approve it (two-person rule) before it can
    be assigned. Validation errors are returned as the error message. Requires the
    Bower.Operator app role or higher.

    .PARAMETER Path
    Privacy profile YAML file.

    .PARAMETER Content
    Privacy profile YAML text.

    .PARAMETER ChangeSummary
    What changed and why, 1-500 characters (shown to reviewers and in the audit).

    .EXAMPLE
    Submit-BowerPrivacyProfile -Path ./contoso.privacy.yaml -ChangeSummary 'Add custom.employee-id detector (PRIV-77)'

    Submits a new version for review.

    .EXAMPLE
    Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml -Remote | Where-Object valid |
        ForEach-Object { Submit-BowerPrivacyProfile -Path ./contoso.privacy.yaml -ChangeSummary 'Tighten secret field names' }

    Validates on the server, then submits only when valid.

    .OUTPUTS
    Bower.PrivacyProfileVersion
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    [OutputType('Bower.PrivacyProfileVersion')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Content')]
        [ValidateNotNullOrEmpty()]
        [string] $Content,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ChangeSummary
    )

    try {
        Assert-BowerReason -Reason $ChangeSummary -Name 'ChangeSummary'
        $profileText = Read-BowerProfileContent -Path $Path -Content $Content
        $target = if ($Path) { "privacy profile '$Path'" } else { 'privacy profile content' }
        if ($PSCmdlet.ShouldProcess($target, 'Submit for review')) {
            Invoke-BowerManagementApi -Method POST -Path '/privacy-profiles' -Body @{ content = $profileText; changeSummary = $ChangeSummary } |
                Add-BowerTypeName -TypeName 'Bower.PrivacyProfileVersion'
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
