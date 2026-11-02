$ErrorActionPreference = 'Stop'
# Soak agent on the WEC collector (MSI). Rendered by lab.py; runs as a SYSTEM task every
# 5 minutes so nothing depends on the operator session. Each tick appends one metadata-only
# sample (process CPU, working set, private bytes, handles, threads, start time, disk, queue
# files, /v1/status queue/jobs/delivery/WEC counters, ForwardedEvents size). At :00 and :30 it
# adds the queue's identities to the accepted union (Bower.LabProbe queue-union), hourly it
# uploads, and SOAK_SECONDS + 30 min after SOAK_START it exports a final record and stops.
#   ACTION=install|tick|final|upload|status
$Action = if ($args.Count -gt 0) { $args[0] } else { '{{ACTION}}' }
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$bucket = '{{Artifacts}}'; $region = '{{REGION}}'; $run = '{{RUN_ID}}'
$start = [long]'{{SOAK_START}}'; $seconds = [long]'{{SOAK_SECONDS}}'
$dir = 'C:\BowerLab\soak'; $root = 'C:\ProgramData\Bower'
New-Item -ItemType Directory -Force $dir | Out-Null
function Put($name) {
    & $aws s3 cp "$dir\$name" "s3://$bucket/results/soak/$run/wec/$name" --region $region --sse AES256 --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "upload failed: $name" }
}
function Sample {
    $at = [DateTimeOffset]::UtcNow
    $row = [ordered]@{ at = $at.ToString('o'); offsetSeconds = [Math]::Round($at.ToUnixTimeMilliseconds() / 1000 - $start, 1); error = $null }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $row.bootAt = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        $service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
        $p = Get-Process -Id $service.ProcessId
        $row.process = [ordered]@{ pid = $p.Id; startedAt = $p.StartTime.ToUniversalTime().ToString('o'); cpuSeconds = $p.TotalProcessorTime.TotalSeconds
            workingSetBytes = $p.WorkingSet64; privateBytes = $p.PrivateMemorySize64; handles = $p.HandleCount; threads = $p.Threads.Count; state = $service.State }
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $row.disk = [ordered]@{ availableBytes = $disk.FreeSpace; totalBytes = $disk.Size }
        $files = [ordered]@{}
        foreach ($n in 'queue.db', 'queue.db-wal', 'queue.db-shm') { $f = Join-Path "$root\state" $n; if (Test-Path $f) { $files[$n] = (Get-Item $f).Length } }
        $row.files = $files
        $token = (Get-Content "$root\secrets\token" -Raw).Trim()
        $s = Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 10
        $token = $null
        $q = $s.queue
        $age = 0; if ($q.oldestUndelivered) { $age = ($at - [DateTimeOffset]::Parse($q.oldestUndelivered)).TotalSeconds }
        $row.queue = [ordered]@{ queued = $q.queued; retrying = $q.retrying; uploading = $q.uploading; delivered = $q.delivered; deadLettered = $q.deadLettered
            totalBytes = $q.totalBytes; undeliveredBytes = $q.undeliveredBytes; pending = $q.queued + $q.retrying + $q.uploading; oldestAgeSeconds = $age }
        $row.status = $s.status
        $jobs = [ordered]@{}; foreach ($j in $s.jobs) { $jobs[$j.id] = [ordered]@{ lastRunAt = $j.lastRunAt; lastState = $j.lastState } }
        $row.jobs = $jobs
        $row.delivery = $s.deliveryActivity
        $row.windowsEventLog = $s.windowsEventLog
        $fwd = Get-WinEvent -ListLog ForwardedEvents
        $row.forwardedEvents = [ordered]@{ records = $fwd.RecordCount; fileBytes = $fwd.FileSize; maxBytes = $fwd.MaximumSizeInBytes }
    } catch { $row.error = $_.Exception.GetType().Name }
    Add-Content "$dir\samples.jsonl" ($row | ConvertTo-Json -Compress -Depth 6)
}
function Union {
    & "$dir\probe.exe" queue-union "$root\state\queue.db" "$dir\accepted.tsv" "$dir\union-last.json"
    if ($LASTEXITCODE -ne 0) { Add-Content "$dir\errors.log" "$([DateTimeOffset]::UtcNow.ToString('o')) union exit $LASTEXITCODE"; return }
    Add-Content "$dir\union.jsonl" (Get-Content "$dir\union-last.json" -Raw)
}
function Upload { foreach ($n in 'samples.jsonl', 'union.jsonl', 'accepted.tsv', 'final.json', 'errors.log') { if (Test-Path "$dir\$n") { Put $n } } }
if ($Action -eq 'install') {
    Copy-Item $PSCommandPath "$dir\agent.ps1" -Force
    & $aws s3 cp "s3://$bucket/artifacts/soak/dc/Bower.LabProbe.exe" "$dir\probe.exe" --region $region --only-show-errors
    if ((Get-FileHash "$dir\probe.exe" -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{PROBE_SHA256}}') { throw 'probe digest mismatch' }
    $next = (Get-Date).Date.AddMinutes([Math]::Ceiling((Get-Date).TimeOfDay.TotalMinutes / 5) * 5)
    $trigger = New-ScheduledTaskTrigger -Once -At $next -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 2)
    Register-ScheduledTask -TaskName 'BowerSoakAgent' -User SYSTEM -RunLevel Highest -Trigger $trigger `
        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $dir\agent.ps1 tick") `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew) | Out-Null
    Sample; Union
    Write-Output "installed BowerSoakAgent first=$($next.ToString('o'))"
    Get-Content "$dir\union-last.json"
    exit 0
}
if ($Action -eq 'tick') {
    if (Test-Path "$dir\final.json") { exit 0 }
    $now = [DateTimeOffset]::UtcNow
    Sample
    if ($now.Minute % 30 -lt 5) { Union }
    if ($now.Minute -lt 5) { Upload }
    if ($now.ToUnixTimeSeconds() -ge $start + $seconds + 1800) { $Action = 'final' } else { exit 0 }
}
if ($Action -eq 'final') {
    Sample; Union
    @{ runId = $run; finalAt = [DateTimeOffset]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content "$dir\final.json"
    Upload
    Disable-ScheduledTask -TaskName 'BowerSoakAgent' | Out-Null
    Get-Content "$dir\union-last.json"
    exit 0
}
if ($Action -eq 'upload') { Union; Upload; Get-Content "$dir\union-last.json"; exit 0 }
if ($Action -eq 'status') {
    Get-Content "$dir\samples.jsonl" -Tail 1
    Get-Content "$dir\union.jsonl" -Tail 1 -ErrorAction SilentlyContinue
    Get-Content "$dir\errors.log" -Tail 5 -ErrorAction SilentlyContinue
    exit 0
}
throw "unknown action $Action"
