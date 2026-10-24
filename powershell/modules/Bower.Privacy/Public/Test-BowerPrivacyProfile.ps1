function Test-BowerPrivacyProfile {
    <#
    .SYNOPSIS
    Validates a Bower privacy profile locally with the bower CLI, or on the management API.

    .DESCRIPTION
    Local mode (default) runs `bower privacy validate FILE [--hmac-key-file KEY]
    [--sample SAMPLE]` and parses its metadata-only JSON summary into an object. The
    profile, key and sample stay on this machine. The bower executable is taken from
    -BowerPath or PATH. A non-zero exit code with a JSON summary is a validation result
    (Valid is $false), not a command failure.

    Remote mode (-Remote) calls POST /api/privacy-profiles/validate through
    Bower.Management (import it and run Connect-BowerManagement first). The server
    validates with a random HMAC key and returns the same metadata summary
    (profileId, version, contentHash, custom detectors, counts and errors).

    The summary never contains matched values or secrets. Every returned property is
    passed through, with Source ('Local' or 'Remote') and Path added.

    .PARAMETER Path
    Privacy profile YAML file.

    .PARAMETER Content
    Privacy profile YAML text (remote mode only).

    .PARAMETER HmacKeyFile
    HMAC key file passed to --hmac-key-file (local mode). When omitted the CLI validates
    with its own validation key.

    .PARAMETER SamplePath
    Sample event file passed to --sample (local mode).

    .PARAMETER BowerPath
    Path to the bower executable. Defaults to bower on PATH.

    .PARAMETER Remote
    Validate on the connected management API instead of locally.

    .EXAMPLE
    Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml

    Validates a profile with the local bower CLI.

    .EXAMPLE
    Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml -SamplePath ./sample-event.json -BowerPath ./bin/bower

    Validates a profile and runs it against a sample event with a specific bower binary.

    .EXAMPLE
    Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -Audience api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml -Remote

    Validates a profile on the management API before submitting it.

    .OUTPUTS
    Bower.PrivacyProfileValidation
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    [OutputType('Bower.PrivacyProfileValidation')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Local', Position = 0, ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Remote', Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(ParameterSetName = 'Remote')]
        [ValidateNotNullOrEmpty()]
        [string] $Content,

        [Parameter(ParameterSetName = 'Local')]
        [ValidateNotNullOrEmpty()]
        [string] $HmacKeyFile,

        [Parameter(ParameterSetName = 'Local')]
        [ValidateNotNullOrEmpty()]
        [string] $SamplePath,

        [Parameter(ParameterSetName = 'Local')]
        [ValidateNotNullOrEmpty()]
        [string] $BowerPath,

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [switch] $Remote
    )

    process {
        try {
            if ($Remote) {
                $result = Invoke-BowerRemotePrivacyValidation -Path $Path -Content $Content
                $source = 'Remote'
            }
            else {
                $result = Invoke-BowerLocalPrivacyValidation -Path $Path -HmacKeyFile $HmacKeyFile -SamplePath $SamplePath -BowerPath $BowerPath
                $source = 'Local'
            }

            $output = [ordered]@{}
            foreach ($property in $result.PSObject.Properties) {
                $output[$property.Name] = $property.Value
            }
            $output['Source'] = $source
            $output['Path'] = if ($Path) { (Resolve-Path -LiteralPath $Path).ProviderPath } else { $null }
            $validation = [pscustomobject]$output
            $validation.PSObject.TypeNames.Insert(0, 'Bower.PrivacyProfileValidation')
            $validation
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
