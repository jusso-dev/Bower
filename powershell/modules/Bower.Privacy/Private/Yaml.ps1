function ConvertTo-BowerNormalizedFieldName {
    <#
    Mirrors PrivacyEngine.NormalizeFieldName: keep char.IsLetterOrDigit characters, each
    lower-cased with char.ToLowerInvariant.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name
    )

    $builder = [System.Text.StringBuilder]::new($Name.Length)
    foreach ($character in $Name.ToCharArray()) {
        if ([char]::IsLetterOrDigit($character)) {
            $null = $builder.Append([char]::ToLowerInvariant($character))
        }
    }
    $builder.ToString()
}
