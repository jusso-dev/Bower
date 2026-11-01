# Upload only fixed, bounded, metadata-only WEC evidence. A checkpoint-only export
# preserves failure diagnostics; it never qualifies a phase or destination.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-WecEvidencePath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'evidence-reparse' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}

function Convert-WecEvidenceJson([string]$Json) {
    # PS5.1 leaves ISO values as strings; newer PS7 can auto-convert them to dates.
    # Preserve the original string contract consistently on both runtimes.
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { return $Json | ConvertFrom-Json -DateKind String }
    return $Json | ConvertFrom-Json
}


function Assert-WecMetadataFields($Value, [string[]]$Required, [string[]]$Optional = @()) {
    if ($Value -isnot [pscustomobject]) { throw 'warmup-object' }
    $names = @($Value.PSObject.Properties.Name)
    if (@($Required | Where-Object { $names -cnotcontains $_ }).Count -or
        @($names | Where-Object { ($Required + $Optional) -cnotcontains $_ }).Count) { throw 'warmup-fields' }
}
function Assert-WecMetadataCount($Value, [long]$Minimum = 0) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt 50000) { throw 'warmup-count' }
}
function Assert-WecMetadataTime($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') { throw 'warmup-time' }
    [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture) | Out-Null
}
function Assert-WecWarmupGenerator($Value) {
    $counts = @('requested', 'requestedRate', 'scheduled', 'completed', 'unexpectedSuccesses', 'maxConcurrency', 'activeAtReturn', 'totalBudgetSeconds')
    $times = @('startedAt', 'endedAt', 'deadlineAt')
    $optional = @('nativeCount', 'forwardedCount', 'queueCount', 'nativeIdsSha256', 'forwardedIdsSha256', 'queueIdsSha256', 'completedAt')
    Assert-WecMetadataFields $Value ($counts + $times + @('kind', 'resultCodes', 'drained')) $optional
    if ($Value.kind -cne 'native-warmup' -or $Value.drained -isnot [bool]) { throw 'warmup-kind' }
    foreach ($name in $counts) { Assert-WecMetadataCount $Value.$name }
    if ($Value.requested -ne 100 -or $Value.requestedRate -ne 10 -or $Value.totalBudgetSeconds -ne 30) { throw 'warmup-budget' }
    foreach ($name in $times) { Assert-WecMetadataTime $Value.$name }
    if ($Value.resultCodes -isnot [pscustomobject] -or @($Value.resultCodes.PSObject.Properties).Count -gt 64) { throw 'warmup-codes' }
    foreach ($entry in $Value.resultCodes.PSObject.Properties) {
        if ($entry.Name -cnotmatch '^-?[0-9]{1,10}$') { throw 'warmup-code' }
        Assert-WecMetadataCount $entry.Value
    }
    foreach ($entry in $Value.PSObject.Properties | Where-Object { $optional -ccontains $_.Name }) {
        if ($entry.Name.EndsWith('Count')) { Assert-WecMetadataCount $entry.Value }
        elseif ($entry.Name.EndsWith('Sha256')) {
            if ($entry.Value -isnot [string] -or $entry.Value -cnotmatch '^[a-f0-9]{64}$') { throw 'warmup-hash' }
        } else { Assert-WecMetadataTime $entry.Value }
    }
}
function Assert-WecWarmupReport($Value) {
    Assert-WecMetadataFields $Value @('kind', 'generator', 'warmupVerified', 'measuredQualification', 'destinationQueryVerified', 'deliveryQualified') @('native', 'forwarded', 'queue', 'acceptedDelta', 'eventWindowEndedAt', 'completedAt', 'identities', 'failure')
    if ($Value.kind -cne 'native-warmup' -or $Value.warmupVerified -isnot [bool]) { throw 'warmup-kind' }
    foreach ($name in 'measuredQualification', 'destinationQueryVerified', 'deliveryQualified') {
        if ($Value.$name -isnot [bool] -or $Value.$name) { throw 'warmup-qualification' }
    }
    Assert-WecWarmupGenerator $Value.generator
    foreach ($entry in $Value.PSObject.Properties) {
        switch -CaseSensitive ($entry.Name) {
            { $_ -cin @('native', 'forwarded') } {
                Assert-WecMetadataFields $entry.Value @('count', 'unique', 'invalidNetworkLogons')
                foreach ($name in 'count', 'unique', 'invalidNetworkLogons') { Assert-WecMetadataCount $entry.Value.$name }
            }
            'queue' {
                Assert-WecMetadataFields $entry.Value @('count', 'exactNativeMatch')
                Assert-WecMetadataCount $entry.Value.count
                if ($entry.Value.exactNativeMatch -isnot [bool]) { throw 'warmup-queue' }
            }
            'acceptedDelta' { Assert-WecMetadataCount $entry.Value -Minimum -50000 }
            { $_ -cin @('eventWindowEndedAt', 'completedAt') } { Assert-WecMetadataTime $entry.Value }
            'identities' {
                if ($entry.Value -isnot [array] -or $entry.Value.Count -gt 3) { throw 'warmup-identities' }
                foreach ($identity in $entry.Value) {
                    Assert-WecMetadataFields $identity @('kind', 'sha256')
                    if ($identity.kind -cnotin @('native', 'forwarded', 'queue') -or $identity.sha256 -isnot [string] -or $identity.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'warmup-identity' }
                }
            }
            'failure' {
                Assert-WecMetadataFields $entry.Value @('exceptionType', 'innerExceptionType', 'hResult', 'category', 'scriptLine', 'staticCode', 'compilerCodes')
                foreach ($name in 'exceptionType', 'innerExceptionType') {
                    $type = $entry.Value.$name
                    if ($name -eq 'innerExceptionType' -and $null -eq $type) { continue }
                    if ($type -isnot [string] -or $type.Length -gt 160 -or $type -cnotmatch '^System\.[A-Za-z0-9_.+]+Exception$') { throw 'warmup-failure-type' }
                }
                if (($entry.Value.hResult -isnot [int] -and $entry.Value.hResult -isnot [long]) -or $entry.Value.hResult -lt [int]::MinValue -or $entry.Value.hResult -gt [int]::MaxValue -or $entry.Value.category -cnotin [Enum]::GetNames([Management.Automation.ErrorCategory])) { throw 'warmup-failure-code' }
                Assert-WecMetadataCount $entry.Value.scriptLine
                $codes = @('source-status-missing', 'event-filter', 'event-count-bound', 'queue-expected-identity', 'queue-malformed-identity', 'queue-stale-expected-identity', 'queue-duplicate-identity', 'owned-config', 'action-must-be-phase-diagnostic-cancel-or-snapshot', 'phase-parameters', 'phase-already-exists', 'synthetic-account-exists', 'existing-loopback-session', 'source-not-running', 'generator-workers-timed-out', 'generator-summary-bound', 'generator-profile', 'generator-warmup-failed', 'warmup-deadline', 'warmup-reconciliation', 'unclassified')
                if ($entry.Value.staticCode -cnotin $codes -or $entry.Value.compilerCodes -isnot [array] -or $entry.Value.compilerCodes.Count -gt 64) { throw 'warmup-failure-code' }
                foreach ($code in $entry.Value.compilerCodes) { if ($code -isnot [string] -or $code -cnotmatch '^CS[0-9]{4}$') { throw 'warmup-compiler-code' } }
            }
        }
    }
}

function Assert-WecCheckpoint($Checkpoint, [string]$RunId, [string]$Phase) {
    $expected = 'deliveryQualified,destinationQueryVerified,generator,mode,nativeVerified,phase,recordType,runId'
    if ((@($Checkpoint.PSObject.Properties.Name | Sort-Object) -join ',') -cne $expected -or
        $Checkpoint.recordType -cne 'generator-checkpoint' -or $Checkpoint.runId -cne $RunId -or $Checkpoint.phase -cne $Phase -or
        $Checkpoint.mode -cnotin @('phase', 'diagnostic') -or $Checkpoint.nativeVerified -isnot [bool] -or $Checkpoint.nativeVerified -or
        $Checkpoint.destinationQueryVerified -isnot [bool] -or $Checkpoint.destinationQueryVerified -or
        $Checkpoint.deliveryQualified -isnot [bool] -or $Checkpoint.deliveryQualified) { throw 'checkpoint-scope' }
    # A checkpoint permits only the generator's reviewed counters, fixed enums,
    # numeric result-code maps and ISO timestamps, never arbitrary log text.
    $integerFields = @('requested', 'scheduled', 'completed', 'unexpectedSuccesses', 'maxConcurrency', 'workerCount',
        'sessionSetupFailures', 'impersonationFailures', 'revertFailures', 'handleCloseFailures', 'sessionCleanupFailures',
        'activeAtReturn', 'workersRemainingAtReturn')
    $booleanFields = @('drained', 'cancelled', 'initialized')
    $numberFields = @('seconds', 'actualRate')
    $enumFields = @{
        executionKind = @('native-windows', 'simulated')
        credentialIsolation = @('per-phase-logon-new-credentials', 'per-worker-logon-new-credentials')
        credentialMode = @('explicit-stable-per-phase', 'implicit-token')
    }
    $mapFields = @('resultCodes', 'sessionResultCodes', 'sessionCleanupCodes', 'initializationFailureReasons')
    $timeFields = @('startedAt', 'endedAt')
    $allowed = $integerFields + $booleanFields + $numberFields + @($enumFields.Keys) + $mapFields + $timeFields
    $names = @($Checkpoint.generator.PSObject.Properties.Name)
    $warmupFields = @('warmupRequired', 'warmupVerified', 'warmup')
    if (@($names | Where-Object { $warmupFields -ccontains $_ }).Count) {
        $allowed += $warmupFields
        foreach ($name in 'warmupRequired', 'warmupVerified') {
            if ($Checkpoint.generator.$name -isnot [bool]) { throw 'checkpoint-warmup-boolean' }
        }
        if ($null -ne $Checkpoint.generator.warmup) { Assert-WecWarmupGenerator $Checkpoint.generator.warmup }
    }
    if ($names.Count -ne $allowed.Count -or @($names | Where-Object { $allowed -cnotcontains $_ }).Count) { throw 'checkpoint-generator-fields' }
    foreach ($name in $integerFields) {
        $value = $Checkpoint.generator.$name
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt 50000) { throw 'checkpoint-counter' }
    }
    foreach ($name in $booleanFields) { if ($Checkpoint.generator.$name -isnot [bool]) { throw 'checkpoint-boolean' } }
    foreach ($name in $numberFields) {
        $value = $Checkpoint.generator.$name
        if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double] -and $value -isnot [decimal]) -or
            [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value) -or $value -lt 0 -or $value -gt 1000000000) { throw 'checkpoint-number' }
    }
    foreach ($name in $enumFields.Keys) { if ($enumFields[$name] -cnotcontains $Checkpoint.generator.$name) { throw 'checkpoint-enum' } }
    foreach ($name in $timeFields) {
        if ($Checkpoint.generator.$name -isnot [string] -or
            $Checkpoint.generator.$name -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') { throw 'checkpoint-time' }
        [DateTimeOffset]::Parse($Checkpoint.generator.$name, [Globalization.CultureInfo]::InvariantCulture) | Out-Null
    }
    foreach ($name in $mapFields) {
        $map = $Checkpoint.generator.$name
        if ($map -isnot [pscustomobject] -or @($map.PSObject.Properties).Count -gt 64) { throw 'checkpoint-code-map' }
        foreach ($property in $map.PSObject.Properties) {
            if ($name -eq 'initializationFailureReasons') {
                if ($property.Name -cnotin @('logon-token', 'impersonation', 'worker-exception', 'worker-start', 'ready-timeout',
                    'native-library-missing', 'native-entrypoint-missing', 'native-library-architecture', 'warmup-evidence', 'warmup-not-verified')) { throw 'checkpoint-reason' }
            } elseif ($property.Name -cnotmatch '^-?[0-9]{1,10}$') { throw 'checkpoint-code' }
            if (($property.Value -isnot [int] -and $property.Value -isnot [long]) -or $property.Value -lt 0 -or $property.Value -gt 50000) { throw 'checkpoint-code-count' }
        }
    }
}

function Get-WecEvidenceExportPlan([string]$Root, [string]$RunId, [string]$Phase) {
    if ($RunId -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or $Phase -cnotmatch '^[a-z][a-z0-9-]{0,39}$') { throw 'export-scope' }
    Assert-WecEvidencePath $Root
    $required = @("$Phase.json", "$Phase-native.ids", "$Phase-forwarded.ids", "$Phase-queue.ids")
    $checkpoint = "$Phase-generator.json"
    $present = @($required | Where-Object { Test-Path -LiteralPath (Join-Path $Root $_) })
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Root $_)) })
    $hasCheckpoint = Test-Path -LiteralPath (Join-Path $Root $checkpoint)
    if ($missing.Count -gt 0 -and -not $hasCheckpoint) { throw 'incomplete-without-checkpoint' }
    $warmup = @("$Phase-warmup.json", "$Phase-warmup-native.ids", "$Phase-warmup-forwarded.ids", "$Phase-warmup-queue.ids")
    $warmupPresent = @($warmup | Where-Object { Test-Path -LiteralPath (Join-Path $Root $_) })
    $warmupMissing = @()
    if ($warmupPresent.Count) { $warmupMissing = @($warmup | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Root $_)) }) }
    $files = @($present) + $warmupPresent
    if ($hasCheckpoint) { $files += $checkpoint }
    foreach ($name in 'outage.jsonl', 'outage-applied.json', 'outage-restored.json') {
        if (Test-Path -LiteralPath (Join-Path $Root $name)) { $files += $name }
    }
    $entries = @()
    foreach ($name in $files) {
        $path = Join-Path $Root $name
        Assert-WecEvidencePath $path
        $item = Get-Item -LiteralPath $path -Force
        $maximum = if ($name -ceq $checkpoint -or $name -ceq "$Phase-warmup.json") { 32768 } else { 4194304 }
        if ($item.PSIsContainer -or $item.Length -gt $maximum) { throw 'export-bound' }
        if ($name -ceq $checkpoint) {
            Assert-WecCheckpoint (Convert-WecEvidenceJson (Get-Content -LiteralPath $path -Raw)) $RunId $Phase
        } elseif ($name -ceq "$Phase-warmup.json") {
            Assert-WecWarmupReport (Convert-WecEvidenceJson (Get-Content -LiteralPath $path -Raw))
        } elseif ($warmup -ccontains $name) {
            foreach ($identity in [IO.File]::ReadLines($path)) {
                if ($identity -cnotmatch '^winevt-[a-f0-9]{32}$') { throw 'warmup-identity-file' }
            }
        } elseif ($name -ceq "$Phase.json") {
            $report = Convert-WecEvidenceJson (Get-Content -LiteralPath $path -Raw)
            if ($report.runId -cne $RunId -or $report.phase -cne $Phase) { throw 'phase-report-scope' }
        }
        $entries += @{ file = $name; bytes = $item.Length; sha256 = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() }
    }
    return @{ schemaVersion = 1; recordType = 'wec-evidence-export'; runId = $RunId; phase = $Phase;
        partialEvidence = ($missing.Count -gt 0 -or $warmupMissing.Count -gt 0); checkpointOnly = ($present.Count -eq 0); checkpointIncluded = [bool]$hasCheckpoint;
        missingPhaseFiles = $missing; warmupIncluded = ($warmupPresent.Count -gt 0); missingWarmupFiles = $warmupMissing; files = $entries; destinationQueryVerified = $false; deliveryQualified = $false }
}

try {
    $root = 'C:\ProgramData\Bower\monitoring'
    Assert-WecEvidencePath $root
    Assert-WecEvidencePath "$root\qualification.json"
    if ((Get-Item -LiteralPath "$root\qualification.json").Length -gt 65536) { throw 'owner-bound' }
    $config = Get-Content "$root\qualification.json" -Raw | ConvertFrom-Json
    $phase = $env:BOWER_WEC_PHASE
    if ($env:OS -ne 'Windows_NT' -or $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2' -or
        $config.runId -cne $env:BOWER_LAB_RUN -or
        $env:BOWER_LAB_BUCKET -cnotmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') { throw 'export-input' }
    # Validate every selected file before uploading any. Missing files require a
    # valid owned checkpoint and are explicitly listed, never treated as success.
    $plan = Get-WecEvidenceExportPlan $root $config.runId $phase
    $aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
    foreach ($entry in $plan.files) {
        $path = Join-Path $root $entry.file
        $key = "results/qualification/$($config.runId)/windows/$phase/$($entry.file)"
        & $aws --region ap-southeast-2 s3 cp $path "s3://$($env:BOWER_LAB_BUCKET)/$key" --sse AES256 --only-show-errors *> $null
        if ($LASTEXITCODE -ne 0) { throw 'export-upload' }
        if ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $entry.sha256 -or
            (Get-Item -LiteralPath $path).Length -ne $entry.bytes) { throw 'evidence-changed-during-export' }
        $entry | ConvertTo-Json -Compress
    }
    $plan | ConvertTo-Json -Depth 5 -Compress
} catch {
    Write-Output '{"evidenceExport":"failed","destinationQueryVerified":false,"deliveryQualified":false}'
    exit 1
}
