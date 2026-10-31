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
    [double] $PagesWarningPercent = 70,
    [double] $PagesCriticalPercent = 85,
    [double] $CertificateWarningDays = 14,
    [double] $CertificateCriticalDays = 2,
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
# Worst first: a CRITICAL finding is never hidden by an UNKNOWN one (exit code 3 > 2).
$rank = @{ 0 = 0; 1 = 1; 3 = 2; 2 = 3 }
$syslogErrorFields = @('connectionsRejected', 'sendersDenied', 'tlsHandshakeFailures', 'malformed', 'oversized',
    'framingErrors', 'timeouts', 'dropped', 'submitFailures', 'receiveErrors', 'parserErrors',
    'tlsReloadFailures', 'tlsRevoked', 'tlsSessionsClosed')
$windowsErrorFields = @('readErrors', 'gaps', 'resets', 'submitFailures', 'parserErrors', 'malformed', 'oversized', 'cursorConflicts')
# The destination refused this collector's identity (credential or role), not an outage.
$credentialFailures = @('destination-azure-credential-failed', 'destination-azure-http-401', 'destination-azure-http-403')
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

# PowerShell 7 turns ISO 8601 strings in JSON into [datetime]; Windows PowerShell 5.1 keeps
# strings. Accept both, and UTC tick strings (how the state file stores times).
function Get-Time($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return ([datetime] $Value).ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return ([datetimeoffset] $Value).UtcDateTime }
    if ("$Value" -match '^\d{15,19}$') { return New-Object DateTime ([long] "$Value"), ([DateTimeKind]::Utc) }
    return [datetimeoffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Get-UtcTick($Value) {
    $time = Get-Time $Value
    if ($null -eq $time) { return $null }
    return $time.Ticks
}

function Get-WorstLevel([int[]] $Levels) {
    $worst = 0
    foreach ($level in $Levels) { if ($rank[$level] -gt $rank[$worst]) { $worst = $level } }
    return $worst
}

function Invoke-Collector([string] $BaseUrl, [string] $Path, [string] $Token, [int] $Timeout) {
    if ($Timeout -lt 1 -or $Timeout -gt 3600) { throw 'Invalid request timeout.' }
    $request = [Net.HttpWebRequest] [Net.WebRequest]::Create($BaseUrl.TrimEnd('/') + $Path)
    $request.Accept = 'application/json'
    $request.AllowAutoRedirect = $false
    $request.Timeout = $Timeout * 1000
    $request.ReadWriteTimeout = $Timeout * 1000
    if ($Token) { $request.Headers['Authorization'] = "Bearer $Token" }
    $response = $null
    $stream = $null
    $buffered = $null
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300 -or
            $response.ContentLength -gt 4194304) { throw 'Invalid collector response.' }
        $stream = $response.GetResponseStream()
        $buffered = New-Object IO.MemoryStream
        $chunk = New-Object byte[] 8192
        while (($read = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
            if ($buffered.Length + $read -gt 4194304) { throw 'Collector response too large.' }
            $buffered.Write($chunk, 0, $read)
        }
        $utf8 = New-Object Text.UTF8Encoding $false, $true
        return ($utf8.GetString($buffered.ToArray()) | ConvertFrom-Json)
    }
    finally {
        if ($null -ne $buffered) { $buffered.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}
# Ask Windows about the actual queue directory, not its drive-letter root: an NTFS
# mounted folder can belong to a different volume. Failure is UNKNOWN, never a C: fallback.
function Get-QueueDiskSpace([string] $Path) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = if ([IO.Directory]::Exists($fullPath)) { $fullPath } else { [IO.Path]::GetDirectoryName($fullPath) }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BowerHealthDiskSpace {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceEx(string path, out ulong available, out ulong total, out ulong free);
}
'@
        [ulong] $available = 0; [ulong] $total = 0; [ulong] $free = 0
        if (-not [BowerHealthDiskSpace]::GetDiskFreeSpaceEx($directory, [ref] $available, [ref] $total, [ref] $free)) {
            throw 'Queue volume free space unavailable.'
        }
        return [pscustomobject]@{ AvailableFreeSpace = $available; TotalSize = $total }
    }
    return New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($fullPath))
}

# Validate before reading the token or making any request. HTTP is permitted only to
# literal loopback authorities; HTTPS retains normal certificate and hostname checks.
$parsedUrl = $null
if ($Url -match '[\x00-\x20\x7f\\]' -or -not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $parsedUrl) -or
    -not $parsedUrl.Host -or $parsedUrl.UserInfo -or $parsedUrl.Query -or $parsedUrl.Fragment -or
    ($parsedUrl.Scheme -ne 'https' -and
     ($parsedUrl.Scheme -ne 'http' -or $Url -notmatch '^http://(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:/|$)'))) {
    Write-Output 'UNKNOWN: monitoring URL must use HTTPS or literal loopback HTTP'
    exit 3
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
elseif ($health -isnot [pscustomobject] -or (Get-Text $health 'status') -isnot [string]) {
    Add-Finding 3 'invalid-response' 'Collector returned an invalid health document.'
}
elseif ((Get-Text $health 'status') -ne 'healthy') {
    $metrics['bower_health_degraded'] = 1
    Add-Finding 1 'health-degraded' 'The collector reports degraded (dead letters or an overdue source).'
}
else {
    $metrics['bower_health_degraded'] = 0
}

$statusValid = $null -ne $status
if ($statusValid) {
  try {
    if ($status -isnot [pscustomobject] -or (Get-Text $status 'queue') -isnot [pscustomobject] -or
        (Get-Text $status 'intake') -isnot [pscustomobject]) { throw 'Invalid status.' }
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

    # In-use pages against the page limit, both reported by the collector: the file never
    # shrinks, so its length would stay high after a drain.
    $pages = Get-Text $status 'queuePages'
    if ($null -ne $pages -and (Get-Number $pages 'pageLimitBytes') -gt 0) {
        $pagesPercent = [double](Get-Text $pages 'usedPercent')
        $metrics['bower_queue_pages_used_bytes'] = Get-Number $pages 'usedBytes'
        $metrics['bower_queue_free_list_bytes'] = Get-Number $pages 'freeListBytes'
        $metrics['bower_queue_page_limit_bytes'] = Get-Number $pages 'pageLimitBytes'
        $metrics['bower_queue_pages_used_percent'] = $pagesPercent
        if ($pagesPercent -ge $PagesCriticalPercent) { Add-Finding 2 'queue-pages' ('Queue database pages are {0:N1}% of the page limit.' -f $pagesPercent) }
        elseif ($pagesPercent -ge $PagesWarningPercent) { Add-Finding 1 'queue-pages' ('Queue database pages are {0:N1}% of the page limit.' -f $pagesPercent) }
    }

    $activity = Get-Text $status 'deliveryActivity'
    $failureCode = [string](Get-Text $activity 'lastFailureCode')
    $failedAt = Get-Time (Get-Text $activity 'lastFailureAt')
    $succeededAt = Get-Time (Get-Text $activity 'lastSuccessfulDeliveryAt')
    if ($failureCode -and $null -ne $failedAt -and ($null -eq $succeededAt -or $succeededAt -le $failedAt) -and
        ($now - $failedAt).TotalSeconds -le $RefusalWindowSeconds) {
        if ($failureCode -in $credentialFailures) {
            Add-Finding 2 'destination-credential' "Delivery is failing with $failureCode and nothing was delivered since; fix the credential or role."
        }
        else {
            Add-Finding 1 'destination-failing' 'Delivery is failing and nothing was delivered since.'
        }
    }

    $sources = @(Get-Text $status 'sources' | Where-Object { $_ -and (Get-Text $_ 'state') -in @('silent', 'never-seen') })
    $metrics['bower_sources_overdue'] = $sources.Count
    foreach ($source in ($sources | Select-Object -First 10)) {
        Add-Finding 1 'source-overdue' ("{0}/{1} is {2}." -f (Get-Text $source 'application'), (Get-Text $source 'environment'), (Get-Text $source 'state'))
    }

    # Process start as UTC ticks: comparing text fails on PowerShell 7, where JSON dates
    # become [datetime] values.
    $startedTicks = Get-UtcTick (Get-Text $intake 'observedSince')
    $state.startedAt = if ($null -ne $startedTicks) { "$startedTicks" } else { $null }
    $previousTicks = if ($null -ne $previous) { Get-UtcTick (Get-Text $previous 'startedAt') } else { $null }
    $sameProcess = $null -ne $startedTicks -and $null -ne $previousTicks -and $startedTicks -eq $previousTicks
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
        $before = if ($sameProcess) { Get-Text (Get-Text $previous 'windowsEventLog') $id } else { $null }
        if ($null -eq $before -and $errors -gt 0) {
            Add-Finding 1 'windows-event-log' ("Subscription {0}: {1} existing error(s); baseline unavailable." -f $id, $errors)
        }
        elseif ($null -ne $before -and $errors -gt (Get-Number $before 'errors')) {
            Add-Finding 1 'windows-event-log' ("Subscription {0}: {1} new read error(s)." -f $id, ($errors - (Get-Number $before 'errors')))
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
        $before = if ($sameProcess) { Get-Text (Get-Text $previous 'syslog') $id } else { $null }
        if ($null -eq $before -and $errors -gt 0) {
            Add-Finding 1 'syslog-errors' ("Listener {0}: {1} existing error(s); baseline unavailable." -f $id, $errors)
        }
        elseif ($null -ne $before -and $errors -gt (Get-Number $before 'errors')) {
            Add-Finding 1 'syslog-errors' ("Listener {0}: {1} new refusal/TLS/framing/drop error(s)." -f $id, ($errors - (Get-Number $before 'errors')))
        }
        if ($null -ne $before -and ($accepted - (Get-Number $before 'accepted')) -gt $ChurnWarningConnections) {
            Add-Finding 1 'syslog-churn' ("Listener {0}: {1} new connections since the last run." -f $id, ($accepted - (Get-Number $before 'accepted')))
        }
        foreach ($certificate in @(@('serverCertificateNotAfter', 'server certificate'), @('clientCertificateAuthorityNotAfter', 'client CA certificate'))) {
            $expires = Get-Time (Get-Text $listener $certificate[0])
            if ($null -eq $expires) { continue }
            $days = ($expires - $now).TotalDays
            $metrics["bower_syslog_certificate_days_left{listener=`"$id`",certificate=`"$($certificate[0])`"}"] = [math]::Round($days, 2)
            if ($days -le $CertificateCriticalDays) { Add-Finding 2 'syslog-certificate' ('Listener {0}: {1} expires in {2:N1} days.' -f $id, $certificate[1], $days) }
            elseif ($days -le $CertificateWarningDays) { Add-Finding 1 'syslog-certificate' ('Listener {0}: {1} expires in {2:N1} days.' -f $id, $certificate[1], $days) }
        }
        $nextUpdate = Get-Time (Get-Text $listener 'clientRevocationListNextUpdate')
        if ($null -ne $nextUpdate) {
            $hours = ($nextUpdate - $now).TotalHours
            if ($hours -le 0) { Add-Finding 2 'syslog-crl' "Listener ${id}: the revocation list is stale; senders are refused." }
            elseif ($hours -le 24) { Add-Finding 1 'syslog-crl' ('Listener {0}: the revocation list must be refreshed within {1:N1} hours.' -f $id, $hours) }
        }
    }
  }
  catch {
    # Conversion errors may contain source text; never print the exception.
    $statusValid = $false
    Add-Finding 3 'invalid-response' 'Collector returned an invalid monitoring document.'
  }
}

# Queue volume free space.
try {
    $drive = Get-QueueDiskSpace $QueuePath
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
    try { $output = & wecutil.exe gr $name 2>&1 }
    catch [System.Management.Automation.CommandNotFoundException] {
        Add-Finding 3 'wec-unknown' 'wecutil.exe is not available; WEC subscription state is unknown.'
        continue
    }
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

if ($null -eq $status -and $TokenFile) {
    Add-Finding 3 'status-unavailable' '/v1/status could not be read.'
}
$levels = @(foreach ($finding in $findings) { ($names.GetEnumerator() | Where-Object { $_.Value -eq $finding.level } | Select-Object -First 1).Key })
$verdict = Get-WorstLevel $levels
$metrics['bower_check_status'] = $verdict

# A failed read keeps the previous baselines: overwriting them with empty state would hide
# every error that happened while the collector could not be read.
if ($StateFile -and $statusValid) {
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
