# Validate selection/ownership/bounds only; never execute exporter main or AWS.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path $PSScriptRoot '../monitoring/export-wec-evidence.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'export parse' }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
$run = 'bower-ws6-20261101-010101'; $phase = 'failed-phase'
$base = if ($env:OS -eq 'Windows_NT') { 'C:\ProgramData' } else { '/private/tmp' }
$root = Join-Path $base ('bower-wec-export-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
$tests = 0
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'unsafe evidence accepted' }
    $script:tests++
}
function New-Checkpoint {
    $generator = [ordered]@{
        executionKind = 'native-windows'; initializationFailureReasons = @{ 'worker-exception' = 1 }
        requested = 1; scheduled = 1; completed = 0; unexpectedSuccesses = 0
        drained = $false; cancelled = $false; seconds = 30.1; actualRate = 0.0
        maxConcurrency = 1; workerCount = 1; resultCodes = @{}
        credentialIsolation = 'per-phase-logon-new-credentials'; credentialMode = 'explicit-stable-per-phase'; initialized = $true
        sessionSetupFailures = 1; impersonationFailures = 0; revertFailures = 0; handleCloseFailures = 0
        sessionResultCodes = @{ '1326' = 1 }; sessionCleanupFailures = 0; sessionCleanupCodes = @{}
        activeAtReturn = 1; workersRemainingAtReturn = 1
        startedAt = '2026-11-01T01:00:00.0000000+00:00'; endedAt = '2026-11-01T01:00:30.1000000+00:00'
    }
    return (Convert-WecEvidenceJson (@{ recordType = 'generator-checkpoint'; runId = $run; phase = $phase; mode = 'diagnostic'; generator = $generator;
        nativeVerified = $false; destinationQueryVerified = $false; deliveryQualified = $false } | ConvertTo-Json -Depth 8))
}
function Write-Checkpoint($Checkpoint) {
    $Checkpoint | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $root "$phase-generator.json") -Encoding UTF8
}
function Write-FullPhase {
    @{ runId = $run; phase = $phase; nativeVerified = $false } | ConvertTo-Json | Set-Content (Join-Path $root "$phase.json")
    foreach ($suffix in 'native', 'forwarded', 'queue') { ('winevt-' + ('a' * 32)) | Set-Content (Join-Path $root "$phase-$suffix.ids") }
}
try {
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    Write-Checkpoint (New-Checkpoint)
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if (-not $plan.partialEvidence -or -not $plan.checkpointOnly -or -not $plan.checkpointIncluded -or
        $plan.files.Count -ne 1 -or $plan.missingPhaseFiles.Count -ne 4 -or $plan.deliveryQualified -or $plan.destinationQueryVerified) { throw 'checkpoint-only contract' }; $tests++
    $processCheckpoint = New-Checkpoint
    $processCheckpoint.generator.credentialIsolation = 'per-process-logon-new-credentials'
    $processCheckpoint.generator.workerCount = 4
    Write-Checkpoint $processCheckpoint
    $processPlan = Get-WecEvidenceExportPlan $root $run $phase
    if (-not $processPlan.partialEvidence -or -not $processPlan.checkpointOnly -or
        $processPlan.files.Count -ne 1 -or $processPlan.missingPhaseFiles.Count -ne 4 -or
        $processPlan.destinationQueryVerified -or $processPlan.deliveryQualified) { throw 'process checkpoint upgraded to qualification' }; $tests++
    Write-Checkpoint (New-Checkpoint)

    [IO.File]::WriteAllText((Join-Path $root 'unrelated-secret.log'), 'synthetic-do-not-export')
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.files.file -contains 'unrelated-secret.log') { throw 'arbitrary file selected' }; $tests++
    Write-FullPhase
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.partialEvidence -or $plan.checkpointOnly -or $plan.files.Count -ne 5) { throw 'full plus checkpoint' }; $tests++
    Remove-Item (Join-Path $root "$phase-generator.json")
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.partialEvidence -or $plan.checkpointIncluded -or $plan.files.Count -ne 4) { throw 'legacy full export' }; $tests++
    Remove-Item (Join-Path $root "$phase-queue.ids")
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    Write-Checkpoint (New-Checkpoint)
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if (-not $plan.partialEvidence -or $plan.checkpointOnly -or ($plan.missingPhaseFiles -join ',') -cne "$phase-queue.ids") { throw 'partial set contract' }; $tests++
    foreach ($change in 'run', 'phase', 'type', 'qualified', 'extra', 'generator-extra', 'generator-code', 'generator-reason', 'generator-isolation') {
        $checkpoint = New-Checkpoint
        switch ($change) {
            run { $checkpoint.runId = 'bower-ws6-20261101-010102' }
            phase { $checkpoint.phase = 'other-phase' }
            type { $checkpoint.recordType = 'arbitrary-log' }
            qualified { $checkpoint.deliveryQualified = $true }
            extra { $checkpoint | Add-Member -NotePropertyName payload -NotePropertyValue 'synthetic-secret' }
            generator-extra { $checkpoint.generator | Add-Member -NotePropertyName password -NotePropertyValue 'synthetic-secret' }
            generator-code { $checkpoint.generator.sessionResultCodes | Add-Member -NotePropertyName secret -NotePropertyValue 1 }
            generator-isolation { $checkpoint.generator.credentialIsolation = 'arbitrary-process-profile' }
            generator-reason { $checkpoint.generator.initializationFailureReasons | Add-Member -NotePropertyName secret -NotePropertyValue 1 }
        }
        Write-Checkpoint $checkpoint
        Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    }
    Write-Checkpoint (New-Checkpoint)
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run '../escape' }
    [IO.File]::AppendAllText((Join-Path $root "$phase-generator.json"), (' ' * 32769))
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    Write-Checkpoint (New-Checkpoint)
    $target = Join-Path $root 'saved-checkpoint.json'
    Move-Item (Join-Path $root "$phase-generator.json") $target
    New-Item -ItemType SymbolicLink -Path (Join-Path $root "$phase-generator.json") -Target $target | Out-Null
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    Remove-Item (Join-Path $root "$phase-generator.json")
    Move-Item $target (Join-Path $root "$phase-generator.json")
    $saved = Join-Path $root 'saved-native.ids'
    Move-Item (Join-Path $root "$phase-native.ids") $saved
    New-Item -ItemType SymbolicLink -Path (Join-Path $root "$phase-native.ids") -Target $saved | Out-Null
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    Remove-Item (Join-Path $root "$phase-native.ids")
    Move-Item $saved (Join-Path $root "$phase-native.ids")
    [IO.File]::WriteAllText((Join-Path $root "$phase-native.ids"), ('x' * 4194305))
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }

    Write-FullPhase
    $warm = Convert-WecEvidenceJson (@{
        kind='native-warmup'; requested=100; requestedRate=10; scheduled=100; completed=100;
        unexpectedSuccesses=0; maxConcurrency=1; activeAtReturn=0; totalBudgetSeconds=30;
        startedAt='2026-11-01T01:00:00Z'; endedAt='2026-11-01T01:00:10Z'; deadlineAt='2026-11-01T01:00:30Z';
        drained=$true; resultCodes=@{ '1326'=100 }
    } | ConvertTo-Json -Depth 5)
    $checkpoint = New-Checkpoint
    $checkpoint.generator | Add-Member -NotePropertyName warmupRequired -NotePropertyValue $true
    $checkpoint.generator | Add-Member -NotePropertyName warmupVerified -NotePropertyValue $true
    $checkpoint.generator | Add-Member -NotePropertyName warmup -NotePropertyValue $warm
    Write-Checkpoint $checkpoint
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.partialEvidence) { throw 'new generator shape rejected' }; $tests++
    $report = @{ kind='native-warmup'; generator=$warm; warmupVerified=$true; measuredQualification=$false; destinationQueryVerified=$false; deliveryQualified=$false }
    $warmPath = Join-Path $root "$phase-warmup.json"
    $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if (-not $plan.partialEvidence -or -not $plan.warmupIncluded -or $plan.missingWarmupFiles.Count -ne 3) { throw 'partial warmup absent' }; $tests++
    foreach ($suffix in 'native', 'forwarded', 'queue') { ('winevt-' + ('a' * 32)) | Set-Content (Join-Path $root "$phase-warmup-$suffix.ids") }
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.partialEvidence -or $plan.files.Count -ne 9) { throw 'full warmup export' }; $tests++
    $warm | Add-Member -NotePropertyName password -NotePropertyValue 'synthetic-secret'
    Write-Checkpoint $checkpoint
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    $warm.PSObject.Properties.Remove('password'); Write-Checkpoint $checkpoint
    $report.payload='synthetic-secret'; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    $report.Remove('payload'); $report.deliveryQualified=$true; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    $report.deliveryQualified=$false; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    'synthetic-secret' | Set-Content (Join-Path $root "$phase-warmup-native.ids")
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    # A rejected identity must release the file immediately, including PS5.1.
    $exclusive = [IO.File]::Open((Join-Path $root "$phase-warmup-native.ids"), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { if (-not $exclusive.CanWrite) { throw 'rejected identity reader retained handle' }; $tests++ } finally { $exclusive.Dispose() }
    ('winevt-' + ('a' * 32)) | Set-Content (Join-Path $root "$phase-warmup-native.ids")

    $report.failure = @{ exceptionType='System.TimeoutException'; innerExceptionType=$null; hResult=-2146233083; category='OperationStopped'; scriptLine=180; staticCode='warmup-deadline'; compilerCodes=@() }
    $report.warmupVerified=$false; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    $plan = Get-WecEvidenceExportPlan $root $run $phase
    if ($plan.files.Count -ne 9 -or $plan.deliveryQualified) { throw 'failed warmup not retained' }; $tests++
    $report.failure.staticCode='arbitrary-secret'; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    $report.failure.staticCode='warmup-deadline'; $report | ConvertTo-Json -Depth 8 | Set-Content $warmPath
    $warm.startedAt='not-a-time'; Write-Checkpoint $checkpoint
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
    $warm.startedAt='2026-11-01T01:00:00Z'; Write-Checkpoint $checkpoint
    [IO.File]::AppendAllText($warmPath, (' ' * 32769))
    Assert-Rejected { Get-WecEvidenceExportPlan $root $run $phase }
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
Write-Output "WEC evidence export validation: $tests checks passed (no AWS or host actions)."
