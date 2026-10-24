function Test-BowerPolicyEvent {
    <#
    .SYNOPSIS
    Runs sample events through Bower's intake offline and reports each decision.

    .DESCRIPTION
    Runs `bower policy test EVENT.json...`: the same redaction, schema validation,
    default-deny policy selection and privacy alerting as the collector, with nothing
    queued, sent or written. Each event file is evaluated as its own /v1/events request.

    The bundle is loaded like the collector's: -PolicyDirectory (default policies/default
    in the current directory), signed packs (-PackPath with -TrustedKeyPath) and an
    optional privacy profile (-PrivacyProfilePath, with -HmacKeyFile for hmac rules).

    Output is metadata only: decision, reasons, policy id, version, hash and score. Event
    content never leaves the CLI. With -ExpectedDecision every result whose decision
    differs also writes a non-terminating error, so `-ErrorAction Stop` fails a build.
    Events are judged at the current time: a sample whose timeGenerated is more than five
    years old or more than five minutes ahead is quarantined, as in the collector.

    .PARAMETER Path
    Event JSON files (one envelope each). Accepts pipeline input from Get-ChildItem.

    .PARAMETER PolicyDirectory
    Policy directory. Defaults to policies/default in the current directory.

    .PARAMETER PackPath
    Signed .bowerpack files to load.

    .PARAMETER TrustedKeyPath
    Public keys (PEM) trusted to sign the packs.

    .PARAMETER PrivacyProfilePath
    Privacy profile YAML to redact with.

    .PARAMETER HmacKeyFile
    Privacy HMAC key file, for profiles with hmac rules.

    .PARAMETER ExpectedDecision
    Decision every event should get: accept, redact-and-accept, reject, quarantine,
    sample, aggregate or dead-letter.

    .PARAMETER BowerPath
    Path to the bower executable. Defaults to bower on PATH.

    .EXAMPLE
    Test-BowerPolicyEvent -Path ./samples/sign-in-failure.json

    Shows whether the sample would be accepted and why.

    .EXAMPLE
    Get-ChildItem ./samples/must-accept -Filter *.json |
        Test-BowerPolicyEvent -PolicyDirectory ./policies/custom -ExpectedDecision accept -ErrorAction Stop

    Fails when any must-accept sample is rejected or quarantined.

    .OUTPUTS
    Bower.PolicyEventResult
    #>
    [CmdletBinding()]
    [OutputType('Bower.PolicyEventResult')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path,

        [ValidateNotNullOrEmpty()]
        [string] $PolicyDirectory = (Join-Path (Get-Location).ProviderPath 'policies/default'),

        [ValidateNotNullOrEmpty()]
        [string[]] $PackPath,

        [ValidateNotNullOrEmpty()]
        [string[]] $TrustedKeyPath,

        [ValidateNotNullOrEmpty()]
        [string] $PrivacyProfilePath,

        [ValidateNotNullOrEmpty()]
        [string] $HmacKeyFile,

        [ValidateSet('accept', 'redact-and-accept', 'reject', 'quarantine', 'sample', 'aggregate', 'dead-letter')]
        [string] $ExpectedDecision,

        [ValidateNotNullOrEmpty()]
        [string] $BowerPath
    )

    begin {
        $files = [System.Collections.Generic.List[string]]::new()
    }

    process {
        try {
            foreach ($item in $Path) {
                $files.Add((Resolve-BowerPolicyFile -Path $item -Name 'Event file'))
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }

    end {
        try {
            $sources = Get-BowerPolicySourceArgument -PolicyDirectory $PolicyDirectory -PackPath $PackPath `
                -TrustedKeyPath $TrustedKeyPath -PrivacyProfilePath $PrivacyProfilePath -HmacKeyFile $HmacKeyFile
            $expected = if ($ExpectedDecision) { $ExpectedDecision.Replace('-', '') } else { $null }
            # The CLI takes at most 1,000 files per run.
            for ($offset = 0; $offset -lt $files.Count; $offset += 1000) {
                $chunk = $files.GetRange($offset, [math]::Min(1000, $files.Count - $offset))
                $arguments = @('policy', 'test') + $chunk + $sources
                $run = Invoke-BowerPolicyCli -ArgumentList $arguments -BowerPath $BowerPath
                foreach ($entry in @($run.Document.results)) {
                    $result = [pscustomobject]@{
                        File               = $entry.file
                        EventId            = $entry.eventId
                        Decision           = $entry.decision
                        WouldQueue         = [bool]$entry.wouldQueue
                        PrivacyAlert       = [bool]$entry.privacyAlert
                        Reasons            = @($entry.reasons)
                        PolicyId           = $entry.policy.policyId
                        PolicyVersion      = $entry.policy.policyVersion
                        PolicyHash         = $entry.policy.policyHash
                        Score              = $entry.policy.score
                        BundleHash         = $run.Document.bundleHash
                        ExpectedDecision   = $expected
                        MatchesExpectation = if ($expected) { $entry.decision -eq $expected } else { $null }
                    }
                    $result.PSObject.TypeNames.Insert(0, 'Bower.PolicyEventResult')
                    $result
                    if ($expected -and -not $result.MatchesExpectation) {
                        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                                [System.InvalidOperationException]::new(
                                    "'$($result.File)' was '$($result.Decision)', expected '$expected': $($result.Reasons -join '; ')"),
                                'BowerPolicyDecisionMismatch',
                                [System.Management.Automation.ErrorCategory]::InvalidResult,
                                $result.File))
                    }
                }
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
