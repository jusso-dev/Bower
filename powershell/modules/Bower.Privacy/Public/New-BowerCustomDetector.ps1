function New-BowerCustomDetector {
    <#
    .SYNOPSIS
    Emits a customDetectors YAML snippet for a Bower privacy profile.

    .DESCRIPTION
    Builds a custom detector (custom redaction rule) definition and writes it as YAML to
    paste into a privacy profile. The structural limits of the privacy profile schema are
    checked here: id format custom.<name> (lowercase letters, digits and hyphens, at most
    64 characters), pattern 1-512 characters, description at most 256 characters, 1-16
    tests.match and 0-16 tests.noMatch samples of 1-1024 characters, and at most 32
    detectors per snippet.

    The restricted pattern syntax, the complexity limit and the test samples are checked
    by the Privacy & Secret Protection Engine, not here. Always run
    Test-BowerPrivacyProfile on the finished profile.

    Pipe several detectors to produce one customDetectors list. Strings are YAML-quoted,
    so regular expression backslashes are written literally.

    .PARAMETER Id
    Detector id, for example custom.employee-id.

    .PARAMETER Pattern
    Regular expression in the restricted Bower syntax.

    .PARAMETER Action
    Privacy action: allow, remove, replace, mask, sha256, hmac, encrypt, alert-only or
    truncate.

    .PARAMETER Match
    Samples the pattern must match (tests.match), 1-16 entries.

    .PARAMETER NoMatch
    Samples the pattern must not match (tests.noMatch), 0-16 entries.

    .PARAMETER Description
    Optional description, at most 256 characters.

    .PARAMETER WholeWord
    Keep only matches bounded by non-word characters (ASCII [A-Za-z0-9_]).

    .PARAMETER IgnoreCase
    Match ASCII letters case-insensitively.

    .PARAMETER ListItemOnly
    Omit the leading customDetectors: line, to append to an existing list.

    .EXAMPLE
    New-BowerCustomDetector -Id custom.employee-id -Pattern 'EMP-\d{6}' -Action mask -WholeWord `
        -Match 'EMP-123456', 'user EMP-000001 logged in' -NoMatch 'EMP-12345' -Description 'Contoso employee numbers'

    Emits a customDetectors list with one detector.

    .EXAMPLE
    @(
        @{ Id = 'custom.ticket-ref'; Pattern = 'TKT-[0-9]{8}'; Action = 'sha256'; Match = @('TKT-12345678') }
        @{ Id = 'custom.badge'; Pattern = 'BDG[0-9]{5}'; Action = 'remove'; Match = @('BDG00042'); IgnoreCase = $true }
    ) | ForEach-Object { [pscustomobject]$_ } | New-BowerCustomDetector | Set-Content ./custom-detectors.yaml

    Emits two detectors in one list from pipeline objects.

    .OUTPUTS
    System.String
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Emits text only.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateScript({ $_.Length -le 64 -and $_ -cmatch '^custom\.[a-z0-9]+(-[a-z0-9]+)*$' }, ErrorMessage = "Custom detector id '{0}' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters).")]
        [string] $Id,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 512)]
        [string] $Pattern,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('allow', 'remove', 'replace', 'mask', 'sha256', 'hmac', 'encrypt', 'alert-only', 'truncate')]
        [string] $Action,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateCount(1, 16)]
        [ValidateLength(1, 1024)]
        [string[]] $Match,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateCount(0, 16)]
        [ValidateLength(1, 1024)]
        [string[]] $NoMatch = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 256)]
        [string] $Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $WholeWord,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $IgnoreCase,

        [switch] $ListItemOnly
    )

    begin {
        $lines = [System.Collections.Generic.List[string]]::new()
        $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    }

    process {
        if (-not $ids.Add($Id)) {
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new("Custom detector id '$Id' is defined more than once."), 'BowerCustomDetectorDuplicate', 'InvalidArgument', $Id))
        }
        if ($ids.Count -gt 32) {
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new('Privacy profile may define at most 32 custom detectors.'), 'BowerCustomDetectorLimit', 'InvalidArgument', $Id))
        }

        $lines.Add("  - id: $Id")
        if ($Description) {
            $lines.Add("    description: $(ConvertTo-BowerYamlScalar -Value $Description)")
        }
        $lines.Add("    pattern: $(ConvertTo-BowerYamlScalar -Value $Pattern)")
        $lines.Add("    ignoreCase: $($IgnoreCase.IsPresent.ToString().ToLowerInvariant())")
        $lines.Add("    wholeWord: $($WholeWord.IsPresent.ToString().ToLowerInvariant())")
        $lines.Add("    action: $($Action.ToLowerInvariant())")
        $lines.Add('    tests:')
        $lines.Add('      match:')
        foreach ($sample in $Match) {
            $lines.Add("        - $(ConvertTo-BowerYamlScalar -Value $sample)")
        }
        if ($NoMatch.Count -gt 0) {
            $lines.Add('      noMatch:')
            foreach ($sample in $NoMatch) {
                $lines.Add("        - $(ConvertTo-BowerYamlScalar -Value $sample)")
            }
        }
        else {
            $lines.Add('      noMatch: []')
        }
    }

    end {
        if ($lines.Count -eq 0) {
            return
        }
        $header = if ($ListItemOnly) { @() } else { @('customDetectors:') }
        (@($header) + $lines) -join "`n"
    }
}
