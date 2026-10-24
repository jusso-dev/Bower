function ConvertTo-BowerSecretFieldName {
    <#
    .SYNOPSIS
    Normalises secret field names the way the Privacy & Secret Protection Engine does.

    .DESCRIPTION
    The engine compares property names after keeping only letters and digits and
    lower-casing them, so x-contoso-signature, X_Contoso_Signature and
    xContosoSignature are the same secret field name. This command shows the normalised
    form, flags duplicates (the engine keeps the first occurrence) and rejects names with
    no letters or digits. With -AsYaml it emits a secretFieldNames snippet (original
    spellings, duplicates removed), enforcing the limit of 64 names of 1-128 characters.

    .PARAMETER Name
    Field names. Accepts pipeline input.

    .PARAMETER AsYaml
    Emit a secretFieldNames YAML snippet instead of objects.

    .EXAMPLE
    'sessionKey', 'session-key', 'x-contoso-signature' | ConvertTo-BowerSecretFieldName

    Shows that sessionKey and session-key normalise to the same name.

    .EXAMPLE
    ConvertTo-BowerSecretFieldName -Name sessionKey, x-contoso-signature -AsYaml

    Emits: secretFieldNames: ['sessionKey', 'x-contoso-signature']

    .OUTPUTS
    Bower.SecretFieldName, or System.String with -AsYaml.
    #>
    [CmdletBinding()]
    [OutputType('Bower.SecretFieldName')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateLength(1, 128)]
        [string[]] $Name,

        [switch] $AsYaml
    )

    begin {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $kept = [System.Collections.Generic.List[string]]::new()
        $failed = $false
    }

    process {
        foreach ($item in $Name) {
            $normalized = ConvertTo-BowerNormalizedFieldName -Name $item
            if ($normalized.Length -eq 0) {
                $failed = $true
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Secret field name '$item' has no letters or digits."), 'BowerSecretFieldNameEmpty', 'InvalidArgument', $item))
                continue
            }

            $duplicate = -not $seen.Add($normalized)
            if (-not $duplicate) {
                $kept.Add($item)
            }
            if (-not $AsYaml) {
                [pscustomobject]@{
                    PSTypeName     = 'Bower.SecretFieldName'
                    Name           = $item
                    NormalizedName = $normalized
                    Duplicate      = $duplicate
                }
            }
        }
    }

    end {
        if (-not $AsYaml -or $failed) {
            return
        }
        if ($kept.Count -gt 64) {
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new('Privacy profile may list at most 64 secretFieldNames of 1-128 characters.'), 'BowerSecretFieldNameLimit', 'InvalidArgument', $null))
        }
        $quoted = foreach ($item in $kept) { ConvertTo-BowerYamlScalar -Value $item }
        "secretFieldNames: [$(@($quoted) -join ', ')]"
    }
}
