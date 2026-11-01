# Standalone bounded SYSTEM sampler. Invoke with monitoring/run.py on the owned host.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Get-BowerSampleBoot {
    return (Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 3).LastBootUpTime.ToUniversalTime().ToString('o')
}

function Get-BowerSampleNumber($Value) {
    if (($Value -isnot [long] -and $Value -isnot [int]) -or $Value -lt 0) { throw 'sample-counter' }
    return [long]$Value
}

function Get-BowerSampleStatusProjection($Status) {
    $queue = [ordered]@{}
    foreach ($key in 'queued', 'retrying', 'uploading', 'delivered', 'deadLettered', 'totalBytes', 'undeliveredBytes') {
        $queue[$key] = Get-BowerSampleNumber $Status.queue.$key
    }
    $queue['pending'] = $queue.queued + $queue.retrying + $queue.uploading
    $queue['count'] = $queue.pending + $queue.delivered + $queue.deadLettered
    $sources = @($Status.windowsEventLog)
    if ($sources.Count -lt 1 -or $sources.Count -gt 16) { throw 'sample-sources' }
    $counters = [ordered]@{}
    foreach ($key in 'eventsRead', 'queued', 'duplicates', 'rejected', 'parserErrors', 'malformed', 'oversized', 'retries', 'submitFailures', 'readErrors', 'gaps', 'resets', 'cursorConflicts') {
        [long]$total = 0
        foreach ($source in $sources) { $total += Get-BowerSampleNumber $source.$key }
        $counters[$key] = $total
    }
    return @{ queue = $queue; sourceCounters = $counters }
}

function Get-BowerSampleHttp([string]$Path, [string]$Token) {
    if ($Path -notin @('/health', '/v1/status')) { throw 'sample-url' }
    $request = [Net.HttpWebRequest]::Create('http://127.0.0.1:4319' + $Path)
    $request.Proxy = $null; $request.AllowAutoRedirect = $false
    $request.Timeout = 3000; $request.ReadWriteTimeout = 3000
    if ($Token) { $request.Headers['Authorization'] = 'Bearer ' + $Token }
    $response = $null; $stream = $null; $memory = New-Object IO.MemoryStream
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw 'sample-http-status' }
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 8192
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($memory.Length + $count -gt 1048576) { throw 'sample-http-bound' }
            $memory.Write($buffer, 0, $count)
        }
        if ($Path -eq '/health') { return $true }
        return ([Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json)
    } finally {
        if ($stream) { $stream.Dispose() }; if ($response) { $response.Dispose() }; $memory.Dispose()
    }
}

function Get-BowerSampleDisk([string]$Directory) {
    $diskType = 'BowerSamplerDisk' -as [type]
    if (-not $diskType) {
        $diskType = Add-Type -PassThru -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BowerSamplerDisk {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceExW(string directory, out ulong available, out ulong total, out ulong free);
}
'@
    }
    [System.UInt64]$available = 0; [System.UInt64]$total = 0; [System.UInt64]$free = 0
    if (-not $diskType::GetDiskFreeSpaceExW($Directory, [ref]$available, [ref]$total, [ref]$free)) {
        throw (New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }
    return @{ availableBytes = $available; totalBytes = $total }
}

function Get-BowerSampleFailure($Failure, [string]$Step) {
    $steps = @('boot-id', 'service-process', 'queue-volume', 'queue-size', 'local-token', 'local-status', 'status-projection', 'health')
    $safeStep = if ($Step -cin $steps) { $Step } else { 'unknown' }
    $nativeCode = $null; $exception = $Failure.Exception
    for ($depth = 0; $depth -lt 4 -and $null -ne $exception; $depth++) {
        if ($exception -is [ComponentModel.Win32Exception]) { $nativeCode = $exception.NativeErrorCode; break }
        $exception = $exception.InnerException
    }
    return @{ step = $safeStep; exceptionType = $Failure.Exception.GetType().FullName;
        hResult = $Failure.Exception.HResult; nativeErrorCode = $nativeCode;
        category = $Failure.CategoryInfo.Category.ToString();
        scriptLine = $(if ($Failure.InvocationInfo) { $Failure.InvocationInfo.ScriptLineNumber } else { 0 }) }
}

function Get-BowerResourceSample([int]$Sequence, [Diagnostics.Stopwatch]$Clock, $Previous) {
    $row = [ordered]@{ sequence = $Sequence; at = [DateTimeOffset]::UtcNow.ToString('o'); elapsedSeconds = $Clock.Elapsed.TotalSeconds
        monotonicSeconds = [Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency
        bootId = $null; metricsAvailable = $false; errorCategory = $null }
    $sampleStep = 'boot-id'
    try {
        $row.bootId = Get-BowerSampleBoot
        $sampleStep = 'service-process'
        $service = Get-CimInstance Win32_Service -Filter "Name='Bower'" -OperationTimeoutSec 3
        if ($service.StartName -ne 'NT SERVICE\Bower' -or $service.ProcessId -le 0) { throw 'sample-service' }
        $process = Get-Process -Id $service.ProcessId -ErrorAction Stop
        $stats = @{ pid = $process.Id; startTicks = $process.StartTime.ToUniversalTime().Ticks
            cpuSeconds = $process.TotalProcessorTime.TotalSeconds; residentBytes = $process.WorkingSet64; cpuPercentOfOneCore = $null }
        if ($Previous -and $Previous.Contains('process')) {
            $old = $Previous.process
            $gap = $row.monotonicSeconds - $Previous.monotonicSeconds
            if ($old.pid -eq $stats.pid -and $old.startTicks -eq $stats.startTicks -and $gap -gt 0) {
                $stats.cpuPercentOfOneCore = [Math]::Max(0, 100 * ($stats.cpuSeconds - $old.cpuSeconds) / $gap)
            }
        }
        $row['process'] = $stats
        $sampleStep = 'queue-volume'
        $row['disk'] = Get-BowerSampleDisk 'C:\ProgramData\Bower\data\'
        $sampleStep = 'queue-size'
        [long]$bytes = 0
        foreach ($suffix in '', '-wal', '-shm') {
            $path = 'C:\ProgramData\Bower\data\bower.db' + $suffix
            if (Test-Path -LiteralPath $path) { $bytes += (Get-Item -LiteralPath $path).Length }
        }
        $row['dbWalBytes'] = $bytes
        $sampleStep = 'local-token'
        $tokenPath = 'C:\ProgramData\Bower\secrets\ingest-token'
        if ((Get-Item -LiteralPath $tokenPath).Length -gt 4096) { throw 'sample-token-bound' }
        $token = [IO.File]::ReadAllText($tokenPath).Trim()
        try {
            $sampleStep = 'local-status'
            $status = Get-BowerSampleHttp '/v1/status' $token
        } finally { $token = $null }
        $sampleStep = 'status-projection'
        $safe = Get-BowerSampleStatusProjection $status
        $status = $null
        $row['queue'] = $safe.queue; $row['sourceCounters'] = $safe.sourceCounters
        $row['healthOk'] = $false
        try { $row.healthOk = Get-BowerSampleHttp '/health' '' } catch {
            $row.healthOk = $false; $row['healthError'] = Get-BowerSampleFailure $_ 'health'
        }
        $row.metricsAvailable = $true
    } catch {
        $row.errorCategory = 'sample-metadata-unavailable'
        $row['errorDetails'] = Get-BowerSampleFailure $_ $sampleStep
    }
    return $row
}

function Write-BowerSampleJson([string]$Path, $Value) {
    $temporary = $Path + '.tmp'
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress) + "`n")
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, $null) } else { [IO.File]::Move($temporary, $Path) }
}

function Read-BowerSampleSet([string]$Root) {
    $path = Join-Path $Root 'samples.jsonl'
    if ((Get-Item -LiteralPath $path).Length -gt 4194304 -or ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'sample-file-bound' }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    # Windows PowerShell 5.1 can retain File.ReadLines' lazy enumerator when
    # validation throws. Always release the handle before returning or failing.
    $reader = [IO.File]::OpenText($path)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ([Text.Encoding]::UTF8.GetByteCount($line) -gt 8192 -or $rows.Count -ge 481) { throw 'sample-row-bound' }
            $rows.Add(($line | ConvertFrom-Json))
        }
    } finally { $reader.Dispose() }
    return ,$rows.ToArray()
}

function Get-BowerSamplePath($Value, [string[]]$Path) {
    foreach ($key in $Path) {
        if ($null -eq $Value) { return $null }
        if ($Value -is [Collections.IDictionary]) {
            if (-not $Value.Contains($key)) { return $null }; $Value = $Value[$key]
        } else {
            $property = $Value.PSObject.Properties[$key]
            if ($null -eq $property) { return $null }; $Value = $property.Value
        }
    }
    return $Value
}

function Get-BowerSampleMaximum([object[]]$Rows, [string[]]$Path) {
    $maximum = $null
    foreach ($row in $Rows) {
        $value = Get-BowerSamplePath $row $Path
        if ($null -ne $value -and ($null -eq $maximum -or $value -gt $maximum)) { $maximum = $value }
    }
    return $maximum
}

function Get-BowerSampleSummary($Scope, [object[]]$Rows, [bool]$Finalized, [string]$CurrentBoot) {
    if ($Rows.Count -gt 481) { throw 'sample-count' }
    $good = @($Rows | Where-Object { $_.metricsAvailable })
    $sameBoot = $Rows.Count -gt 0 -and $CurrentBoot -eq $Scope.bootId
    $maximumGap = $null; $restarts = 0; $resets = 0
    $increases = [ordered]@{}; $maxima = [ordered]@{}
    $fields = @('eventsRead', 'queued', 'duplicates', 'rejected', 'parserErrors', 'malformed', 'oversized', 'retries', 'submitFailures', 'readErrors', 'gaps', 'resets', 'cursorConflicts')
    foreach ($key in $fields) { $increases[$key] = 0; $maxima[$key] = Get-BowerSampleMaximum $Rows @('sourceCounters', $key) }
    $previous = $null; $previousGood = $null; $previousProcess = $null; $minimumDisk = $null
    for ($index = 0; $index -lt $Rows.Count; $index++) {
        $row = $Rows[$index]
        if ($row.sequence -ne $index) { throw 'sample-sequence' }
        if ($row.bootId -ne $Scope.bootId) { $sameBoot = $false }
        $disk = Get-BowerSamplePath $row @('disk', 'availableBytes')
        if ($null -ne $disk -and ($null -eq $minimumDisk -or $disk -lt $minimumDisk)) { $minimumDisk = $disk }
        if ($previous) {
            $gap = $row.monotonicSeconds - $previous.monotonicSeconds
            if ($sameBoot -and ($gap -lt 0 -or [double]::IsNaN($gap) -or [double]::IsInfinity($gap))) { throw 'sample-clock' }
            if ($null -eq $maximumGap -or $gap -gt $maximumGap) { $maximumGap = $gap }

        }
        $currentProcess = Get-BowerSamplePath $row @('process')
        if ($null -ne $currentProcess) {
            if ($null -ne $previousProcess -and ($currentProcess.startTicks -ne $previousProcess.startTicks -or $currentProcess.pid -ne $previousProcess.pid)) { $restarts++ }
            $previousProcess = $currentProcess
        }
        if ($row.metricsAvailable) {
            if ($previousGood) {
                foreach ($key in $fields) {
                    $delta = $row.sourceCounters.$key - $previousGood.sourceCounters.$key
                    if ($delta -lt 0) { $resets++ } else { $increases[$key] += $delta }
                }
            }
            $previousGood = $row
        }
        $previous = $row
    }
    $elapsed = 0; $firstAt = $null; $lastAt = $null
    if ($Rows.Count) { $elapsed = $Rows[-1].elapsedSeconds; $firstAt = $Rows[0].at; $lastAt = $Rows[-1].at }
    return [ordered]@{ schemaVersion = 1; runId = $Scope.runId; role = 'windows'; scope = $Scope.scope; planSha256 = $Scope.planSha256
        durationSeconds = $Scope.durationSeconds; intervalSeconds = 15; sampleCount = $Rows.Count; availableSampleCount = $good.Count
        failedSampleCount = $Rows.Count - $good.Count; firstSampleAt = $firstAt; lastSampleAt = $lastAt; observedDurationSeconds = $elapsed
        maxSampleGapSeconds = $maximumGap; bootUnchanged = $sameBoot; processRestartCount = $restarts; sourceCounterResetCount = $resets
        sourceCounterIncreases = $increases; sourceCounterMaxima = $maxima; peakPendingCount = (Get-BowerSampleMaximum $Rows @('queue', 'pending'))
        peakQueueCount = (Get-BowerSampleMaximum $Rows @('queue', 'count')); peakQueueBytes = (Get-BowerSampleMaximum $Rows @('queue', 'totalBytes'))
        peakUndeliveredBytes = (Get-BowerSampleMaximum $Rows @('queue', 'undeliveredBytes')); peakDeadLetterCount = (Get-BowerSampleMaximum $Rows @('queue', 'deadLettered'))
        peakDbWalBytes = (Get-BowerSampleMaximum $Rows @('dbWalBytes')); peakProcessResidentBytes = (Get-BowerSampleMaximum $Rows @('process', 'residentBytes'))
        peakCpuPercentOfOneCore = (Get-BowerSampleMaximum $Rows @('process', 'cpuPercentOfOneCore')); minimumQueueVolumeAvailableBytes = $minimumDisk
        finalized = $Finalized; samplingComplete = [bool]($Finalized -and $sameBoot -and $good.Count -gt 0 -and $good.Count -eq $Rows.Count -and
            $Rows[0].elapsedSeconds -ge 0 -and $Rows[0].elapsedSeconds -le 15 -and
            $elapsed - $Rows[0].elapsedSeconds -ge $Scope.durationSeconds - 15 -and $null -ne $maximumGap -and $maximumGap -le 30); deliveryQualified = $false }
}

function Invoke-BowerSamplerWorker([string]$Root) {
    $scope = Get-Content (Join-Path $Root 'scope.json') -Raw | ConvertFrom-Json
    $clock = [Diagnostics.Stopwatch]::StartNew(); $previous = $null; $finished = $false; $stream = $null
    try {
        $stream = [IO.File]::Open((Join-Path $Root 'samples.jsonl'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        for ($index = 0; $index -le [int]($scope.durationSeconds / 15); $index++) {
            while ($clock.Elapsed.TotalSeconds -lt $index * 15) { Start-Sleep -Milliseconds 100 }
            $row = Get-BowerResourceSample -Sequence $index -Clock $clock -Previous $previous
            $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($row | ConvertTo-Json -Depth 8 -Compress) + "`n")
            if ($bytes.Length -gt 8192 -or $stream.Length + $bytes.Length -gt 4194304) { throw 'sample-cap' }
            $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true); $previous = $row
        }
        $finished = $true
    } catch { $finished = $false } finally { if ($stream) { $stream.Dispose() } }
    $rows = Read-BowerSampleSet $Root
    Write-BowerSampleJson -Path (Join-Path $Root 'summary.json') -Value (Get-BowerSampleSummary -Scope $scope -Rows $rows -Finalized $finished -CurrentBoot (Get-BowerSampleBoot))
}

try {
    $run = $env:BOWER_LAB_RUN; $scopeName = $env:BOWER_SAMPLE_SCOPE; $plan = $env:BOWER_PLAN_SHA256; $bucket = $env:BOWER_LAB_BUCKET
    if ($env:OS -ne 'Windows_NT' -or $run -cnotmatch '^bower-ws6-\d{8}-\d{6}$' -or $scopeName -cnotmatch '^[a-z][a-z0-9-]{0,39}$' -or
        $plan -cnotmatch '^[a-f0-9]{64}$' -or $bucket -cnotmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2') { throw 'sampler-scope' }
    $owned = Get-Content 'C:\ProgramData\Bower\monitoring\qualification.json' -Raw | ConvertFrom-Json
    if ($owned.runId -cne $run) { throw 'owned-run' }
    $root = "C:\ProgramData\Bower\monitoring\resource-samples\$run\$scopeName-$plan"
    $taskName = 'BowerSample-' + $scopeName + '-' + $plan.Substring(0, 16)
    $action = $env:BOWER_SAMPLE_ACTION
    if (-not $action) { $action = 'start' }
    if ($action -eq 'probe') {
        $probe = Get-BowerResourceSample -Sequence 0 -Clock ([Diagnostics.Stopwatch]::StartNew()) -Previous $null
        @{ recordType = 'resource-probe'; runId = $run; scope = $scopeName; planSha256 = $plan; sample = $probe;
            samplingComplete = $false; deliveryQualified = $false } | ConvertTo-Json -Depth 8 -Compress
        if (-not $probe.metricsAvailable) { exit 1 }
    } elseif ($action -eq 'start') {
        [int]$duration = 4200
        if ($env:BOWER_SAMPLE_SECONDS -and -not [int]::TryParse($env:BOWER_SAMPLE_SECONDS, [ref]$duration)) { throw 'sample-duration' }
        if ($duration -lt 60 -or $duration -gt 7140 -or $duration % 15 -ne 0 -or (Test-Path $root) -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'sample-duration-or-existing-scope' }
        New-Item -ItemType Directory -Path $root | Out-Null
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($identity in 'S-1-5-18', 'S-1-5-32-544') {
            $sid = New-Object Security.Principal.SecurityIdentifier($identity)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $root -AclObject $acl
        $code = '$ErrorActionPreference = ''Stop''; Set-StrictMode -Version Latest' + "`n"
        foreach ($name in 'Get-BowerSampleBoot', 'Get-BowerSampleNumber', 'Get-BowerSampleStatusProjection', 'Get-BowerSampleHttp', 'Get-BowerSampleDisk', 'Get-BowerSampleFailure',
            'Get-BowerResourceSample', 'Write-BowerSampleJson', 'Read-BowerSampleSet', 'Get-BowerSamplePath', 'Get-BowerSampleMaximum', 'Get-BowerSampleSummary', 'Invoke-BowerSamplerWorker') {
            $code += "function $name {`n" + (Get-Command $name -CommandType Function).Definition + "`n}`n"
        }
        $code += "Invoke-BowerSamplerWorker -Root '$root'`n"
        [IO.File]::WriteAllText("$root\worker.ps1", $code, (New-Object Text.UTF8Encoding($false)))
        $scope = @{ schemaVersion = 1; runId = $run; scope = $scopeName; planSha256 = $plan; bucket = $bucket; role = 'windows'
            durationSeconds = $duration; intervalSeconds = 15; bootId = (Get-BowerSampleBoot); startedAt = [DateTimeOffset]::UtcNow.ToString('o')
            workerSha256 = (Get-FileHash "$root\worker.ps1").Hash.ToLowerInvariant() }
        Write-BowerSampleJson "$root\scope.json" $scope
        $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        Register-ScheduledTask -TaskName $taskName -User SYSTEM -RunLevel Highest `
            -Action (New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -File `"$root\worker.ps1`"") `
            -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($duration + 60)) -MultipleInstances IgnoreNew) | Out-Null
        Start-ScheduledTask -TaskName $taskName
        @{ started = $true; task = $taskName; scope = $scopeName; planSha256 = $plan; hardLimitSeconds = $duration + 60 } | ConvertTo-Json -Compress
    } elseif ($action -in @('status', 'export')) {
        $scope = Get-Content "$root\scope.json" -Raw | ConvertFrom-Json
        if ($scope.runId -cne $run -or $scope.scope -cne $scopeName -or $scope.planSha256 -cne $plan -or $scope.bucket -cne $bucket -or $scope.role -cne 'windows') { throw 'saved-scope' }
        $finalized = $false
        if (Test-Path "$root\summary.json") { $finalized = (Get-Content "$root\summary.json" -Raw | ConvertFrom-Json).finalized -eq $true }
        $rows = Read-BowerSampleSet $root
        $report = Get-BowerSampleSummary -Scope $scope -Rows $rows -Finalized $finalized -CurrentBoot (Get-BowerSampleBoot)
        if ($action -eq 'export') {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if ($task.State -notin @('Ready', 'Disabled') -and -not (Test-Path "$root\summary.json")) { throw 'sampler-still-running' }
            Write-BowerSampleJson "$root\export-summary.json" $report
            $exports = @()
            foreach ($name in 'scope.json', 'samples.jsonl', 'export-summary.json') {
                $path = Join-Path $root $name
                $item = Get-Item -LiteralPath $path
                if ($item.Length -gt 4194304 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'export-bound' }
                $key = "results/resource-sampling/$run/windows/$scopeName/$plan/$name"
                & 'C:\Program Files\Amazon\AWSCLIV2\aws.exe' s3 cp $path "s3://$bucket/$key" --sse AES256 --only-show-errors *> $null
                if ($LASTEXITCODE -ne 0) { throw 'sample-upload' }
                $exports += @{ key = $key; bytes = $item.Length; sha256 = (Get-FileHash $path).Hash.ToLowerInvariant() }
            }
            $report['exports'] = $exports
        }
        $report | ConvertTo-Json -Depth 8 -Compress
    } else { throw 'sampler-action' }
} catch { Write-Output '{"sampler":"failed","deliveryQualified":false}'; exit 1 }
