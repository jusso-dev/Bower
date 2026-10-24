function Invoke-BowerPrivacyProfilePreview {
    <#
    .SYNOPSIS
    Previews how a privacy profile redacts a sample event, on the management API.

    .DESCRIPTION
    Calls POST /api/privacy-profiles/preview with the profile content and a sample JSON
    event (at most 64 KiB). The server uses a random per-request HMAC key and neither
    persists nor logs the sample or the result. Returns validity, errors, the redacted
    sample and the findings (detector, action and path). Use synthetic samples; do not
    paste production secrets. Requires the Bower.Operator app role or higher.

    .PARAMETER Path
    Privacy profile YAML file.

    .PARAMETER Content
    Privacy profile YAML text.

    .PARAMETER Sample
    Sample event: a JSON string or an object (serialised to JSON).

    .PARAMETER SamplePath
    File containing the sample JSON event.

    .EXAMPLE
    Invoke-BowerPrivacyProfilePreview -Path ./contoso.privacy.yaml -SamplePath ./sample-event.json

    Shows the redacted sample and findings.

    .EXAMPLE
    $sample = @{ attributes = @{ note = 'employee EMP-123456 reset MFA' } }
    (Invoke-BowerPrivacyProfilePreview -Path ./contoso.privacy.yaml -Sample $sample).findings

    Lists which detectors matched a synthetic sample.

    .OUTPUTS
    Bower.PrivacyProfilePreview
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType('Bower.PrivacyProfilePreview')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [Parameter(Mandatory, ParameterSetName = 'PathSampleFile')]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Content')]
        [Parameter(Mandatory, ParameterSetName = 'ContentSampleFile')]
        [ValidateNotNullOrEmpty()]
        [string] $Content,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [Parameter(Mandatory, ParameterSetName = 'Content')]
        [ValidateNotNull()]
        [object] $Sample,

        [Parameter(Mandatory, ParameterSetName = 'PathSampleFile')]
        [Parameter(Mandatory, ParameterSetName = 'ContentSampleFile')]
        [ValidateNotNullOrEmpty()]
        [string] $SamplePath
    )

    try {
        $profileText = Read-BowerProfileContent -Path $Path -Content $Content
        $sampleText = if ($SamplePath) {
            [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $SamplePath -ErrorAction Stop).ProviderPath, [System.Text.Encoding]::UTF8)
        }
        elseif ($Sample -is [string]) {
            $Sample
        }
        else {
            $Sample | ConvertTo-Json -Depth 32 -Compress
        }

        try {
            $null = $sampleText | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw [System.ArgumentException]::new('Sample must be valid JSON.')
        }
        if ([System.Text.Encoding]::UTF8.GetByteCount($sampleText) -gt 65536) {
            throw [System.ArgumentException]::new('Sample must be at most 64 KiB of JSON.')
        }

        Invoke-BowerManagementApi -Method POST -Path '/privacy-profiles/preview' -Body @{ content = $profileText; sample = $sampleText } |
            Add-BowerTypeName -TypeName 'Bower.PrivacyProfilePreview'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
