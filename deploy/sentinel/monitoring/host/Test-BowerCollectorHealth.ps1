<#
.SYNOPSIS
Local Bower collector health check for Windows hosts (Windows PowerShell 5.1 or PowerShell 7).

.DESCRIPTION
Reads the collector's /health and token-protected /v1/status on the local listener, plus
free space on the queue volume and the WEC subscription runtime state (wecutil), and
returns one verdict as the process exit code:

  0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (Nagios/Icinga/Zabbix convention)

With -WriteEventLog it also writes the verdict to the Application log (source
Bower.HealthCheck, event 9100 OK, 9101 WARNING, 9102 CRITICAL, 9103 UNKNOWN), where Azure
Monitor Agent, Windows Event Forwarding or a SIEM agent can collect it. Metadata only:
never prints the token, payloads, event ids or endpoints.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Test-BowerCollectorHealth.ps1 `
  -TokenFile C:\ProgramData\Bower\secrets\ingest-token -WecSubscription bower-forwarded -WriteEventLog
#>
[CmdletBinding()]
param(
    [string] $Url = 'http://127.0.0.1:4319',
    [string] $TokenFile,
    [string] $QueuePath = 'C:\ProgramData\Bower\state\queue.db',
    [long] $QueueMaxBytes = 10GB,
    [int] $BacklogWarningSeconds = 900,
    [int] $BacklogCriticalSeconds = 3600,
    [double] $StorageWarningPercent = 40,
    [double] $StorageCriticalPercent = 60,
    [double] $FileWarningPercent = 70,
    [double] $FileCriticalPercent = 85,
    [double] $DiskWarningPercent = 20,
    [double] $DiskCriticalPercent = 10,
    [int] $RefusalWindowSeconds = 900,
    [string[]] $WecSubscription = @(),
    [string] $StateFile,
    [int] $ChurnWarningConnections = 5,
    [int] $TimeoutSeconds = 5,
    [ValidateSet('Text', 'Json')]
    [string] $Format = 'Text',
    [switch] $WriteEventLog
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$names = @{ 0 = 'OK'; 1 = 'WARNING'; 2 = 'CRITICAL'; 3 = 'UNKNOWN' }
$syslogErrorFields = @('connectionsRejected', 'sendersDenied', 'tlsHandshakeFailures', 'malformed', 'oversized',
    'framingErrors', 'timeouts', 'dropped', 'submitFailures', 'receiveErrors', 'parserErrors')
$windowsErrorFields = @('readErrors', 'gaps', 'resets', 'submitFailures', 'parserErrors', 'cursorConflicts')
$findings = New-Object System.Collections.Generic.List[object]
$metrics = [ordered]@{}

function Add-Finding([int] $Level, [string] $Code, [string] $Detail) {
    $findings.Add([pscustomobject]@{ level = $names[$Level]; code = $Code; detail = $Detail })
}

function Get-Number($Object, [string] $Name) {
    if ($null -eq $Object) { return 0 }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return 0 }
    return [long] $property.Value
}

function Get-Text($Object, [string] $Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-Time($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return ([datetime] $Value).ToUniversalTime() }
    return [datetimeoffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Invoke-Collector([string] $BaseUrl, [string] $Path, [string] $Token, [int] $Timeout) {
    $headers = @{ Accept = 'application/json' }
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }
    return Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + $Path) -Headers $headers -TimeoutSec $Timeout -UseBasicParsing
}

$now = [datetime]::UtcNow
$token = $null
if ($TokenFile) {
    try { $token = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }
    catch { Write-Output 'UNKNOWN: token file unreadable'; exit 3 }
}

$health = $null
$status = $null
try { $health = Invoke-Collector $Url '/health' $null $TimeoutSeconds } catch { $health = $null }
if ($null -ne $health -and $token) {
    try { $status = Invoke-Collector $Url '/v1/status' $token $TimeoutSeconds } catch { $status = $null }
}

$previous = $null
if ($StateFile -and (Test-Path -LiteralPath $StateFile)) {
    try { $previous = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $previous = $null }
}
$state = [ordered]@{ startedAt = $null; syslog = @{}; windowsEventLog = @{} }

$metrics['bower_up'] = [int]($null -ne $health)
if ($null -eq $health) {
    Add-Finding 2 'collector-unreachable' 'The collector did not answer /health.'
}
elseif ((Get-Text $health 'status') -ne 'healthy') {
    $metrics['bower_health_degraded'] = 1
    Add-Finding 1 'health-degraded' 'The collector reports degraded (dead letters or an overdue source).'
}
else {
    $metrics['bower_health_degraded'] = 0
}

if ($null -ne $status) {
    $queue = Get-Text $status 'queue'
    $undelivered = (Get-Number $queue 'queued') + (Get-Number $queue 'retrying') + (Get-Number $queue 'uploading')
    $dead = Get-Number $queue 'deadLettered'
    $undeliveredBytes = Get-Number $queue 'undeliveredBytes'
    $oldest = Get-Time (Get-Text $queue 'oldestUndelivered')
    $age = 0
    if ($null -ne $oldest) { $age = [math]::Max(0, [long]($now - $oldest).TotalSeconds) }
    $used = 0.0
    if ($QueueMaxBytes -gt 0) { $used = 100.0 * $undeliveredBytes / $QueueMaxBytes }
    $metrics['bower_queue_undelivered_events'] = $undelivered
    $metrics['bower_queue_dead_lettered_events'] = $dead
    $metrics['bower_queue_undelivered_bytes'] = $undeliveredBytes
    $metrics['bower_queue_oldest_undelivered_age_seconds'] = $age
    $metrics['bower_queue_capacity_used_percent'] = [math]::Round($used, 2)
    if ($dead -gt 0) { Add-Finding 1 'dead-letters' "$dead event(s) set aside; review and use the audited replay." }
    if ($age -ge $BacklogCriticalSeconds) { Add-Finding 2 'backlog' "Oldest undelivered event is $age s old." }
    elseif ($age -ge $BacklogWarningSeconds) { Add-Finding 1 'backlog' "Oldest undelivered event is $age s old." }
    if ($used -ge $StorageCriticalPercent) { Add-Finding 2 'queue-storage' ('Undelivered data is {0:N1}% of BOWER_QUEUE_MAX_BYTES.' -f $used) }
    elseif ($used -ge $StorageWarningPercent) { Add-Finding 1 'queue-storage' ('Undelivered data is {0:N1}% of BOWER_QUEUE_MAX_BYTES.' -f $used) }

    $intake = Get-Text $status 'intake'
    $metrics['bower_intake_capacity_refusals_total'] = (Get-Number $intake 'capacityRefusals') + (Get-Number $intake 'privacyAlertRefusals')
    $lastRefusal = Get-Time (Get-Text $intake 'lastRefusalAt')
    if ($null -ne $lastRefusal -and ($now - $lastRefusal).TotalSeconds -le $RefusalWindowSeconds) {
        Add-Finding 2 'capacity-refusals' 'Intake was refused for queue capacity within the refusal window.'
    }

    $sources = @(Get-Text $status 'sources' | Where-Object { $_ -and (Get-Text $_ 'state') -in @('silent', 'never-seen') })
    $metrics['bower_sources_overdue'] = $sources.Count
    foreach ($source in ($sources | Select-Object -First 10)) {
        Add-Finding 1 'source-overdue' ("{0}/{1} is {2}." -f (Get-Text $source 'application'), (Get-Text $source 'environment'), (Get-Text $source 'state'))
    }

    $started = Get-Text $intake 'observedSince'
    if ($started -is [datetime]) { $started = $started.ToUniversalTime().ToString('o') }
    $state.startedAt = $started
    $sameProcess = $null -ne $previous -and $null -ne $started -and "$(Get-Text $previous 'startedAt')" -eq "$started"
    foreach ($subscription in @(Get-Text $status 'windowsEventLog')) {
        if ($null -eq $subscription) { continue }
        $id = [string](Get-Text $subscription 'id')
        $errors = 0
        foreach ($field in $windowsErrorFields) { $errors += Get-Number $subscription $field }
        $state.windowsEventLog[$id] = @{ errors = $errors }
        $metrics["bower_windows_event_log_errors_total{subscription=`"$id`"}"] = $errors
        $subscriptionState = Get-Text $subscription 'state'
        if ($subscriptionState -notin @('starting', 'running', 'backpressure')) {
            Add-Finding 2 'windows-event-log' "Subscription $id is $subscriptionState."
        }
        if ($sameProcess) {
            $before = Get-Text (Get-Text $previous 'windowsEventLog') $id
            if ($null -ne $before -and $errors -gt (Get-Number $before 'errors')) {
                Add-Finding 1 'windows-event-log' ("Subscription {0}: {1} new read error(s)." -f $id, ($errors - (Get-Number $before 'errors')))
            }
        }
    }
    foreach ($listener in @(Get-Text $status 'syslog')) {
        if ($null -eq $listener) { continue }
        $id = [string](Get-Text $listener 'id')
        $errors = 0
        foreach ($field in $syslogErrorFields) { $errors += Get-Number $listener $field }
        $accepted = Get-Number $listener 'connectionsAccepted'
        $state.syslog[$id] = @{ errors = $errors; accepted = $accepted }
        $metrics["bower_syslog_errors_total{listener=`"$id`"}"] = $errors
        $metrics["bower_syslog_connections_accepted_total{listener=`"$id`"}"] = $accepted
        if ($sameProcess) {
            $before = Get-Text (Get-Text $previous 'syslog') $id
            if ($null -ne $before -and $errors -gt (Get-Number $before 'errors')) {
                Add-Finding 1 'syslog-errors' ("Listener {0}: {1} new refusal/TLS/framing/drop error(s)." -f $id, ($errors - (Get-Number $before 'errors')))
            }
            if ($null -ne $before -and ($accepted - (Get-Number $before 'accepted')) -gt $ChurnWarningConnections) {
                Add-Finding 1 'syslog-churn' ("Listener {0}: {1} new connections since the last run." -f $id, ($accepted - (Get-Number $before 'accepted')))
            }
        }
    }
}

# Queue database against its SQLite page limit, (4 x cap + 16 MiB) / 4: the file stops growing
# there ("database or disk is full") before undelivered payloads reach BOWER_QUEUE_MAX_BYTES.
if (Test-Path -LiteralPath $QueuePath -PathType Leaf) {
    $fileBytes = (Get-Item -LiteralPath $QueuePath).Length
    $fileLimit = [math]::Floor(($QueueMaxBytes * 4 + 16MB) / 4)
    $filePercent = 100.0 * $fileBytes / $fileLimit
    $metrics['bower_queue_file_bytes'] = $fileBytes
    $metrics['bower_queue_file_limit_used_percent'] = [math]::Round($filePercent, 2)
    if ($filePercent -ge $FileCriticalPercent) { Add-Finding 2 'queue-file' ('Queue database is at {0:N1}% of its page limit.' -f $filePercent) }
    elseif ($filePercent -ge $FileWarningPercent) { Add-Finding 1 'queue-file' ('Queue database is at {0:N1}% of its page limit.' -f $filePercent) }
}

# Queue volume free space.
try {
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($QueuePath))
    $drive = New-Object IO.DriveInfo $root
    $freePercent = 100.0 * $drive.AvailableFreeSpace / $drive.TotalSize
    $metrics['bower_queue_volume_free_bytes'] = $drive.AvailableFreeSpace
    $metrics['bower_queue_volume_free_percent'] = [math]::Round($freePercent, 2)
    if ($freePercent -le $DiskCriticalPercent) { Add-Finding 2 'disk-free' ('Queue volume has {0:N1}% free.' -f $freePercent) }
    elseif ($freePercent -le $DiskWarningPercent) { Add-Finding 1 'disk-free' ('Queue volume has {0:N1}% free.' -f $freePercent) }
}
catch {
    Add-Finding 3 'disk-unknown' 'Queue volume free space could not be read.'
}

# WEC subscription runtime state: a source-initiated subscription lists each event source.
foreach ($name in $WecSubscription) {
    $output = & wecutil.exe gr $name 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Finding 2 'wec-subscription' "WEC subscription $name could not be read (wecutil exit $LASTEXITCODE)."
        continue
    }
    # The first RunTimeStatus is the subscription's; each later one belongs to an event source.
    $statuses = @([regex]::Matches(($output | Out-String), 'RunTimeStatus:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
    $runtime = if ($statuses.Count -gt 0) { $statuses[0] } else { 'Unknown' }
    $metrics["bower_wec_subscription_active{subscription=`"$name`"}"] = [int]($runtime -eq 'Active')
    if ($runtime -ne 'Active') {
        Add-Finding 2 'wec-subscription' "WEC subscription $name is $runtime."
    }
    $inactive = @($statuses | Select-Object -Skip 1 | Where-Object { $_ -ne 'Active' }).Count
    $metrics["bower_wec_sources_not_active{subscription=`"$name`"}"] = $inactive
    if ($inactive -gt 0) {
        Add-Finding 1 'wec-source' "WEC subscription $name has $inactive event source(s) not Active."
    }
}

$verdict = 0
foreach ($finding in $findings) {
    $level = ($names.GetEnumerator() | Where-Object { $_.Value -eq $finding.level } | Select-Object -First 1).Key
    if ($level -gt $verdict) { $verdict = $level }
}
if ($verdict -eq 0 -and $null -eq $status -and $TokenFile) {
    $verdict = 3
    Add-Finding 3 'status-unavailable' '/v1/status could not be read.'
}
$metrics['bower_check_status'] = $verdict

if ($StateFile) {
    try { $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8 } catch { Write-Verbose 'State file not written.' }
}

$summary = if ($findings.Count -eq 0) { 'collector healthy' } else { ($findings | ForEach-Object { "$($_.code): $($_.detail)" }) -join '; ' }
if ($WriteEventLog) {
    $source = 'Bower.HealthCheck'
    if (-not [Diagnostics.EventLog]::SourceExists($source)) {
        [Diagnostics.EventLog]::CreateEventSource($source, 'Application')
    }
    $entryType = switch ($verdict) {
        0 { [Diagnostics.EventLogEntryType]::Information }
        1 { [Diagnostics.EventLogEntryType]::Warning }
        default { [Diagnostics.EventLogEntryType]::Error }
    }
    # WriteEntry works in Windows PowerShell 5.1 and PowerShell 7 (which has no Write-EventLog).
    [Diagnostics.EventLog]::WriteEntry($source, "$($names[$verdict]): $summary", $entryType, 9100 + $verdict)
}

if ($Format -eq 'Json') {
    [ordered]@{ status = $names[$verdict]; checkedAt = $now.ToString('o'); findings = $findings; metrics = $metrics } |
        ConvertTo-Json -Depth 5 -Compress
}
else {
    "$($names[$verdict]): $summary"
}
exit $verdict
