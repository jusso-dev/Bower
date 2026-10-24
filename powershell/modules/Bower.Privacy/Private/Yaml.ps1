function ConvertTo-BowerYamlScalar {
    <#
    Quotes a string as a YAML scalar. Plain printable text uses single quotes (only ''
    needs escaping, so regex backslashes stay literal). Text with control characters uses
    double quotes with escapes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value -notmatch '[\x00-\x1F\x7F\u0085\u2028\u2029]') {
        return "'" + $Value.Replace("'", "''") + "'"
    }

    $builder = [System.Text.StringBuilder]::new('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int]$character
        $escaped = switch ($code) {
            0x5C { '\\' }
            0x22 { '\"' }
            0x0A { '\n' }
            0x0D { '\r' }
            0x09 { '\t' }
            default {
                if ($code -lt 0x20 -or $code -eq 0x7F -or $code -eq 0x85 -or $code -eq 0x2028 -or $code -eq 0x2029) {
                    '\u{0:X4}' -f $code
                }
                else {
                    [string]$character
                }
            }
        }
        $null = $builder.Append($escaped)
    }
    $null = $builder.Append('"')
    $builder.ToString()
}

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
