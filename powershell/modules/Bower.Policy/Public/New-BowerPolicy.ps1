function New-BowerPolicy {
    <#
    .SYNOPSIS
    Writes a Bower telemetry policy (bower.security/v1 TelemetryPolicy) as YAML.

    .DESCRIPTION
    Builds the policy document the collector loads: metadata, match (event categories
    and/or types), required, at-least-one and recommended investigation fields, the
    decision with its minimum value score, and optional routing. Every string is quoted,
    so values cannot change the YAML structure.

    Without -Path the YAML text is returned. With -Path it is written (UTF-8, no BOM)
    after ShouldProcess confirmation; an existing file is kept unless -Force is given.
    Run Test-BowerPolicy and Test-BowerPolicyEvent afterwards: the bower CLI remains the
    authority on whether the policy loads and what it selects. Policy changes need a
    version bump and review before deployment.

    .PARAMETER Id
    Policy id, for example BWR-POL-ORDERS-EXPORT.

    .PARAMETER Name
    Human-readable policy name.

    .PARAMETER Version
    Semantic version (major.minor.patch).

    .PARAMETER Owner
    Owning team.

    .PARAMETER EventCategory
    Event categories the policy matches.

    .PARAMETER EventType
    Event types the policy matches. At least one category or type is required.

    .PARAMETER RequiredField
    Fields every matched event must carry, for example timeGenerated or actor.userId.

    .PARAMETER AtLeastOne
    Fields of which at least one must be present.

    .PARAMETER RecommendedField
    Fields that raise the value score and produce warnings when missing.

    .PARAMETER Action
    Decision for matching events: accept (default), redact-and-accept, reject, quarantine,
    sample, aggregate or dead-letter.

    .PARAMETER MinimumValueScore
    Events scoring below this (0-100) are rejected. Default 70.

    .PARAMETER NeverSample
    Marks the event type as never sampled.

    .PARAMETER ReviewDate
    Date by which the policy must be reviewed.

    .PARAMETER RoutingProfile
    Optional routing profile.

    .PARAMETER RoutingDestination
    Optional routing destination.

    .PARAMETER Path
    File to write. When omitted the YAML text is returned.

    .PARAMETER Force
    Overwrite an existing file.

    .EXAMPLE
    New-BowerPolicy -Id BWR-POL-ORDERS-EXPORT -Name 'Order exports' -Version 1.0.0 -Owner 'Security Operations' `
        -EventCategory data-access -EventType sensitive_data_exported `
        -RequiredField timeGenerated, eventType, actor.userId, target.id -RecommendedField request.correlationId `
        -Path ./policies/custom/orders-export.yaml

    Writes a policy that accepts sensitive data exports carrying actor and target.

    .EXAMPLE
    New-BowerPolicy -Id BWR-POL-NOISE -Name 'Page views' -Version 1.0.0 -Owner 'Platform' -EventType page_view -Action reject

    Returns the YAML for an explicit reject policy without writing a file.

    .OUTPUTS
    System.String, System.IO.FileInfo
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([string], [System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateLength(1, 256)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidatePattern('^\d+\.\d+\.\d+$')]
        [string] $Version,

        [Parameter(Mandatory)]
        [ValidateLength(1, 256)]
        [string] $Owner,

        [ValidateCount(1, 64)]
        [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,127}$')]
        [string[]] $EventCategory,

        [ValidateCount(1, 64)]
        [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,127}$')]
        [string[]] $EventType,

        [ValidateCount(1, 64)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9.]{0,127}$')]
        [string[]] $RequiredField,

        [ValidateCount(1, 64)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9.]{0,127}$')]
        [string[]] $AtLeastOne,

        [ValidateCount(1, 64)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9.]{0,127}$')]
        [string[]] $RecommendedField,

        [ValidateSet('accept', 'redact-and-accept', 'reject', 'quarantine', 'sample', 'aggregate', 'dead-letter')]
        [string] $Action = 'accept',

        [ValidateRange(0, 100)]
        [int] $MinimumValueScore = 70,

        [switch] $NeverSample,

        [datetime] $ReviewDate,

        [ValidateLength(1, 128)]
        [string] $RoutingProfile,

        [ValidateLength(1, 128)]
        [string] $RoutingDestination,

        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [switch] $Force
    )

    try {
        if (-not $EventCategory -and -not $EventType) {
            throw [System.ArgumentException]::new('Provide -EventCategory, -EventType or both: a policy must match something.')
        }

        $lines = [System.Collections.Generic.List[string]]::new()
        $list = {
            param([string] $Key, [string[]] $Values, [string] $Indent)
            if (-not $Values) {
                $lines.Add("$Indent${Key}: []")
                return
            }
            $lines.Add("$Indent${Key}:")
            foreach ($value in $Values) {
                $lines.Add("$Indent  - $(ConvertTo-BowerYamlScalar -Value $value)")
            }
        }

        $lines.Add('apiVersion: bower.security/v1')
        $lines.Add('kind: TelemetryPolicy')
        $lines.Add('')
        $lines.Add('metadata:')
        $lines.Add("  id: $(ConvertTo-BowerYamlScalar -Value $Id)")
        $lines.Add("  name: $(ConvertTo-BowerYamlScalar -Value $Name)")
        $lines.Add("  version: $(ConvertTo-BowerYamlScalar -Value $Version)")
        $lines.Add("  owner: $(ConvertTo-BowerYamlScalar -Value $Owner)")
        if ($PSBoundParameters.ContainsKey('ReviewDate')) {
            $lines.Add("  reviewDate: $($ReviewDate.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))")
        }
        $lines.Add('')
        $lines.Add('match:')
        & $list 'eventCategories' $EventCategory '  '
        & $list 'eventTypes' $EventType '  '
        $lines.Add('')
        $lines.Add('requirements:')
        & $list 'requiredFields' $RequiredField '  '
        & $list 'atLeastOne' $AtLeastOne '  '
        & $list 'recommendedFields' $RecommendedField '  '
        $lines.Add('')
        $lines.Add('decision:')
        $lines.Add("  action: $Action")
        $lines.Add("  minimumValueScore: $MinimumValueScore")
        $lines.Add("  neverSample: $($NeverSample.IsPresent.ToString().ToLowerInvariant())")
        if ($RoutingProfile -or $RoutingDestination) {
            $lines.Add('')
            $lines.Add('routing:')
            if ($RoutingProfile) {
                $lines.Add("  profile: $(ConvertTo-BowerYamlScalar -Value $RoutingProfile)")
            }
            if ($RoutingDestination) {
                $lines.Add("  destination: $(ConvertTo-BowerYamlScalar -Value $RoutingDestination)")
            }
        }
        $yaml = ($lines -join "`n") + "`n"

        if (-not $Path) {
            return $yaml
        }

        $target = [System.IO.Path]::GetFullPath($Path, (Get-Location).ProviderPath)
        if ((Test-Path -LiteralPath $target) -and -not $Force) {
            throw [System.IO.IOException]::new("'$target' already exists. Pass -Force to overwrite it.")
        }
        if ($PSCmdlet.ShouldProcess($target, "Write telemetry policy '$Id' $Version")) {
            [System.IO.File]::WriteAllText($target, $yaml, [System.Text.UTF8Encoding]::new($false))
            Get-Item -LiteralPath $target
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
