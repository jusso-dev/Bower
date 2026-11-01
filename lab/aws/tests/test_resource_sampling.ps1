# Pure functions and worker syntax only. No native service, task, token or HTTP calls.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../monitoring/sample-resources-windows.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'sampler syntax' }
$functions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }
$checks = 0
function Assert-Sample($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }; $script:checks++
}
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert-Sample $failed 'invalid sampler fixture accepted'
}
$queue = @{}; foreach ($key in 'queued', 'retrying', 'uploading', 'delivered', 'deadLettered', 'totalBytes', 'undeliveredBytes') { $queue[$key] = 1 }
$fields = 'eventsRead', 'queued', 'duplicates', 'rejected', 'parserErrors', 'malformed', 'oversized', 'retries', 'submitFailures', 'readErrors', 'gaps', 'resets', 'cursorConflicts'
$counters = @{}; foreach ($key in $fields) { $counters[$key] = 2 }; $counters['payload'] = 'SECRET'
$projection = Get-BowerSampleStatusProjection ([pscustomobject]@{ queue = $queue; windowsEventLog = @($counters, $counters); token = 'SECRET' })
Assert-Sample ($projection.queue.pending -eq 3 -and $projection.queue.count -eq 5) 'queue aggregation'
Assert-Sample ($projection.sourceCounters.retries -eq 4) 'source aggregation'
Assert-Sample (($projection | ConvertTo-Json -Depth 8) -notmatch 'SECRET') 'raw metadata leaked'
foreach ($value in @($true, -1, 1.5, '1', $null)) { Assert-Rejected { Get-BowerSampleNumber $value } }
Assert-Rejected { Get-BowerSampleStatusProjection ([pscustomobject]@{ queue = $queue; windowsEventLog = @() }) }
Assert-Rejected { Get-BowerSampleStatusProjection ([pscustomobject]@{ queue = $queue; windowsEventLog = @([pscustomobject]@{}) }) }
$scope = [pscustomobject]@{ runId = 'bower-ws6-20261101-011000'; scope = 'outage'; planSha256 = ('a' * 64); durationSeconds = 60; bootId = 'boot' }
function New-SampleRows {
    return ,@(0..4 | ForEach-Object {
        $index = $_; $sourceCounters = @{}; foreach ($key in $fields) { $sourceCounters[$key] = $index }
        [pscustomobject]@{ sequence = $index; at = '2026-11-01T00:00:00Z'; elapsedSeconds = $index * 15; monotonicSeconds = 1000 + $index * 15
            bootId = 'boot'; metricsAvailable = $true; sourceCounters = $sourceCounters; dbWalBytes = 10 + $index
            process = @{ pid = 1; startTicks = 123; residentBytes = $index * 100; cpuPercentOfOneCore = $index }
            disk = @{ availableBytes = 1000 - $index * 10 }; queue = @{ pending = $index; count = $index + 1; totalBytes = 50 + $index; undeliveredBytes = $index; deadLettered = 0 } }
    })
}
$rows = New-SampleRows
$report = Get-BowerSampleSummary $scope $rows $true 'boot'
Assert-Sample $report.samplingComplete 'complete sample set rejected'
Assert-Sample (-not $report.deliveryQualified) 'sampler claimed delivery'
Assert-Sample ($report.peakProcessResidentBytes -eq 400 -and $report.minimumQueueVolumeAvailableBytes -eq 960) 'resource peaks'
Assert-Sample ($report.sourceCounterIncreases.retries -eq 4 -and $report.processRestartCount -eq 0) 'counter deltas'
Assert-Sample (-not (Get-BowerSampleSummary $scope $rows $false 'boot').samplingComplete) 'unfinished passed'
Assert-Sample (-not (Get-BowerSampleSummary $scope $rows $true 'changed').samplingComplete) 'boot change passed'
Assert-Sample (-not (Get-BowerSampleSummary $scope @() $false 'boot').samplingComplete) 'empty passed'
foreach ($case in 'failure', 'gap', 'late-start', 'short', 'boot-change') {
    $rows = New-SampleRows
    switch ($case) {
        'failure' { $rows[2].metricsAvailable = $false }
        'gap' { $rows[-1].monotonicSeconds += 31 }
        'late-start' { foreach ($row in $rows) { $row.elapsedSeconds += 50 } }
        'short' { $rows = @($rows[0], $rows[1]) }
        'boot-change' { $rows[-1].bootId = 'changed' }
    }
    Assert-Sample (-not (Get-BowerSampleSummary $scope $rows $true 'boot').samplingComplete) "incomplete passed: $case"
}
$rows = New-SampleRows; $rows[2].sourceCounters.retries = 0; $rows[2].process.startTicks = 456
$rows[3].metricsAvailable = $false; $rows[3].process.residentBytes = 900; $rows[4].PSObject.Properties.Remove('process')
$report = Get-BowerSampleSummary $scope $rows $true 'boot'
Assert-Sample ($report.sourceCounterResetCount -eq 1 -and $report.processRestartCount -eq 2) 'reset detection'
Assert-Sample ($report.peakProcessResidentBytes -eq 900) 'partial sample resource lost'
$rows = New-SampleRows; $rows[1].sequence = 7
Assert-Rejected { Get-BowerSampleSummary $scope $rows $true 'boot' }
$rows = New-SampleRows; $rows[1].monotonicSeconds = -1
Assert-Rejected { Get-BowerSampleSummary $scope $rows $true 'boot' }
function Assert-SampleFileReleased([string]$Path) {
    # On Windows this immediately fails if a rejected lazy reader still owns
    # the file. No GC, sleeps or cleanup retries may hide a leaked handle.
    $exclusive = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Assert-Sample $exclusive.CanWrite 'sample reader retained file handle' } finally { $exclusive.Dispose() }
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('bower-sampler-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
try {
    $path = Join-Path $directory 'samples.jsonl'
    [IO.File]::WriteAllText($path, '')
    Assert-Sample ((Read-BowerSampleSet $directory).Count -eq 0) 'empty JSONL shape'
    $rows = New-SampleRows
    [IO.File]::WriteAllText($path, ($rows[0] | ConvertTo-Json -Depth 8 -Compress) + "`n")
    Assert-Sample ((Read-BowerSampleSet $directory).Count -eq 1) 'single JSONL shape'
    [IO.File]::WriteAllText($path, (($rows | ForEach-Object { $_ | ConvertTo-Json -Depth 8 -Compress }) -join "`n") + "`n")
    Assert-Sample ((Read-BowerSampleSet $directory).Count -eq 5) 'many JSONL shape'
    Assert-SampleFileReleased $path
    [IO.File]::WriteAllText($path, ("{}`n" * 482))
    Assert-Rejected { Read-BowerSampleSet $directory }
    Assert-SampleFileReleased $path
    [IO.File]::WriteAllText($path, (' ' * 8193) + "`n")
    Assert-Rejected { Read-BowerSampleSet $directory }
    Assert-SampleFileReleased $path
    [IO.File]::WriteAllText($path, '{invalid-json')
    Assert-Rejected { Read-BowerSampleSet $directory }
    Assert-SampleFileReleased $path
    Write-BowerSampleJson (Join-Path $directory 'summary.json') $report
    $saved = Get-Content (Join-Path $directory 'summary.json') -Raw | ConvertFrom-Json
    Assert-Sample ($saved.peakProcessResidentBytes -eq 900) 'summary serialization'
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
$code = '$ErrorActionPreference = ''Stop''; Set-StrictMode -Version Latest' + "`n"
foreach ($function in $functions) { $code += "function $($function.Name) {`n" + (Get-Command $function.Name -CommandType Function).Definition + "`n}`n" }
[Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors) | Out-Null
Assert-Sample ($errors.Count -eq 0) 'standalone worker function serialization'
# Exercise the native disk-call binding with a fake type and without the PS7-only
# ulong accelerator. This reproduces PS5.1 type resolution without calling kernel32.
Add-Type -TypeDefinition @'
public static class BowerSamplerDisk {
    public static string RequestedDirectory;
    public static bool Fail;
    public static bool GetDiskFreeSpaceExW(string directory, out ulong available, out ulong total, out ulong free) {
        RequestedDirectory=directory; available=123456789; total=987654321; free=234567890; return !Fail;
    }
}
'@
$accelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$originalUlong = $accelerators::Get['ulong']
try {
    if ($originalUlong) { $accelerators::Remove('ulong') | Out-Null }
    $volume = Get-BowerSampleDisk 'C:\ProgramData\Bower\data\'
    Assert-Sample ($volume.availableBytes -eq 123456789 -and $volume.totalBytes -eq 987654321) 'PS5.1 UInt64 binding'
    Assert-Sample ([BowerSamplerDisk]::RequestedDirectory -ceq 'C:\ProgramData\Bower\data\') 'actual queue directory replaced by drive root'
} finally { if ($originalUlong) { $accelerators::Add('ulong', $originalUlong) } }
try { throw (New-Object ComponentModel.Win32Exception 5) } catch { $failure = Get-BowerSampleFailure $_ 'queue-volume' }
Assert-Sample ($failure.step -ceq 'queue-volume' -and $failure.nativeErrorCode -eq 5 -and $failure.scriptLine -gt 0) 'native disk error code lost'
try { throw 'SECRET response body Authorization: Bearer secret-token' } catch { $failure = Get-BowerSampleFailure $_ 'status-projection' }
$failureJson = $failure | ConvertTo-Json -Compress
Assert-Sample ($failureJson -notmatch 'SECRET|Authorization|Bearer|secret-token|Message|PositionMessage' -and $failure.step -ceq 'status-projection') 'exception body leaked'
try { throw 'SECRET' } catch { $failure = Get-BowerSampleFailure $_ 'SECRET untrusted-step' }
Assert-Sample ($failure.step -ceq 'unknown' -and ($failure | ConvertTo-Json -Compress) -notmatch 'SECRET') 'untrusted step leaked'
# An actual sample failure retains already collected process metrics and the safe step.
function Get-BowerSampleBoot { return 'test-boot' }
function Get-CimInstance { return [pscustomobject]@{ StartName = 'NT SERVICE\Bower'; ProcessId = $PID } }
function Get-Process { return [Diagnostics.Process]::GetCurrentProcess() }
[BowerSamplerDisk]::Fail = $true
$sample = Get-BowerResourceSample 0 ([Diagnostics.Stopwatch]::StartNew()) $null
Assert-Sample (-not $sample.metricsAvailable -and $sample.errorDetails.step -ceq 'queue-volume') 'disk failure not localized'
Assert-Sample ($sample.Contains('process') -and -not $sample.Contains('disk') -and $sample.process.residentBytes -gt 0) 'partial process observation lost'
Assert-Sample ($sample.errorDetails.exceptionType -and $sample.errorDetails.hResult -is [int] -and $sample.errorDetails.scriptLine -gt 0) 'safe failure details missing'
Write-Output "Resource sampler validation: $checks checks passed (native Windows/task/HTTP execution not performed)."
