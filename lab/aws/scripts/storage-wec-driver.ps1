# Storage-pressure scenarios on the disposable WEC/collector host (Windows PowerShell 5.1).
# A sequence-numbered generator makes real NTLM LDAP bind failures (nonexistent ws3wNNNNNNN
# accounts) against the lab domain controller; its Security 4625 events are forwarded by
# WEF into ForwardedEvents and read by Bower. The driver blocks only the Bower service's
# HTTPS, fills the dedicated Q: volume with a bounded filler, restarts the service and
# samples metadata every five seconds. Output: counters, sizes, states, times and digests.
param(
    [Parameter(Mandatory = $true)][ValidateSet('queue-cap', 'watermarks', 'disk-full', 'reconcile', 'probe')][string]$Scenario,
    [ValidateRange(1, 100)][int]$Rate = 50,
    [ValidateRange(10, 1800)][int]$Hold = 120,
    [ValidateRange(60, 7200)][int]$Limit = 3600,
    [ValidatePattern('^172\.31\.233\.\d{1,3}$')][string]$Target = $env:BOWER_DC_IP
)
$ErrorActionPreference = 'Stop'
$work = 'C:\ws3'; $logs = "$work\logs"; $filler = 'Q:\ws3-filler'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$secrets = 'C:\ProgramData\Bower\secrets'
$token = (Get-Content "$secrets\ingest-token" -Raw).Trim()
$journal = "$logs\$Scenario.jsonl"
$events = New-Object System.Collections.ArrayList
$samples = New-Object System.Collections.ArrayList

Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -ReferencedAssemblies System.DirectoryServices.Protocols, System, System.Core -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Threading;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public sealed class Ws3Generator {
    private readonly string target; private readonly int rate; private readonly string stateFile;
    private Thread thread; private volatile bool stopping;
    public long First; public long Next; public long Failed; public long Unexpected; public double MaximumLagSeconds;
    public Ws3Generator(string target, int rate, string stateFile) {
        this.target = target; this.rate = rate; this.stateFile = stateFile;
        Next = File.Exists(stateFile) ? long.Parse(File.ReadAllText(stateFile)) : 1; First = Next;
    }
    public void Start() { thread = new Thread(Run); thread.IsBackground = true; thread.Start(); }
    public void Stop() { stopping = true; if (thread != null) thread.Join(60000); File.WriteAllText(stateFile, Next.ToString()); }
    // One synchronous bind at a time: each attempt is one native 4625 in sequence order.
    private void Run() {
        var clock = Stopwatch.StartNew(); long sent = 0;
        var server = new LdapDirectoryIdentifier(target, 389, false, false);
        while (!stopping) {
            double due = (double)sent / rate; double lag = clock.Elapsed.TotalSeconds - due;
            if (lag < 0) { Thread.Sleep(TimeSpan.FromSeconds(-lag)); } else if (lag > MaximumLagSeconds) { MaximumLagSeconds = lag; }
            long seq = Next;
            try {
                using (var connection = new LdapConnection(server)) {
                    connection.AuthType = AuthType.Ntlm; connection.Timeout = TimeSpan.FromSeconds(5);
                    connection.Credential = new NetworkCredential("ws3w" + seq.ToString("D7"), "synthetic-invalid-" + Guid.NewGuid().ToString("N"), "WS3");
                    try { connection.Bind(); Interlocked.Increment(ref Unexpected); }
                    catch (LdapException error) { if (error.ErrorCode != 49) Interlocked.Increment(ref Failed); }
                }
            } catch { Interlocked.Increment(ref Failed); }
            Next = seq + 1; sent++;
            if (sent % 50 == 0) File.WriteAllText(stateFile, Next.ToString());
        }
    }
}

// Read-only queue access through the SQLite library the collector ships.
public static class Ws3Queue {
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_open_v2(byte[] name, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int bytes, out IntPtr statement, IntPtr tail);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_step(IntPtr statement);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr sqlite3_column_text(IntPtr statement, int column);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_column_bytes(IntPtr statement, int column);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_finalize(IntPtr statement);
    [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_close(IntPtr db);
    static byte[] Utf8(string value) { return System.Text.Encoding.UTF8.GetBytes(value + "\0"); }
    public static List<string[]> Query(string path, string sql, int columns) {
        IntPtr db; IntPtr statement; var rows = new List<string[]>();
        if (sqlite3_open_v2(Utf8(path), out db, 1, IntPtr.Zero) != 0) throw new IOException("open failed");
        try {
            if (sqlite3_prepare_v2(db, Utf8(sql), -1, out statement, IntPtr.Zero) != 0) throw new IOException("prepare failed");
            try {
                int rc;
                while ((rc = sqlite3_step(statement)) == 100) {
                    var row = new string[columns];
                    for (int i = 0; i < columns; i++) {
                        IntPtr text = sqlite3_column_text(statement, i); int length = sqlite3_column_bytes(statement, i);
                        if (text != IntPtr.Zero) { var bytes = new byte[length]; Marshal.Copy(text, bytes, 0, length); row[i] = System.Text.Encoding.UTF8.GetString(bytes); }
                    }
                    rows.Add(row);
                }
                if (rc != 101) throw new IOException("step failed " + rc);
            } finally { sqlite3_finalize(statement); }
        } finally { sqlite3_close(db); }
        return rows;
    }
}
'@

function Now { [DateTimeOffset]::UtcNow.ToString('o') }
function Write-Journal($record) { ($record | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Encoding utf8 $journal }
function Mark($name, $values = @{}) {
    $record = [ordered]@{ at = (Now); event = $name }
    foreach ($key in $values.Keys) { $record[$key] = $values[$key] }
    [void]$events.Add($record); Write-Journal ([ordered]@{ kind = 'event' } + $record); $script:phase = $name
}
function Get-Status {
    try { Invoke-RestMethod -Uri 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 10 } catch { $null }
}
function Get-Free { $volume = Get-Volume -DriveLetter Q; @($volume.SizeRemaining, $volume.Size) }
function Test-Blocked { [bool](Get-NetFirewallRule -DisplayName 'ws3-block' -ErrorAction SilentlyContinue) }
function Block { if (-not (Test-Blocked)) { New-NetFirewallRule -DisplayName 'ws3-block' -Direction Outbound -Service Bower -Protocol TCP -RemotePort 443 -Action Block | Out-Null } }
function Unblock { Remove-NetFirewallRule -DisplayName 'ws3-block' -ErrorAction SilentlyContinue }
function Set-Filler([long]$freeTarget) {
    $free = (Get-Free)[0]; $current = if (Test-Path $filler) { (Get-Item $filler).Length } else { 0 }
    $size = [Math]::Max(0, $current + $free - $freeTarget)
    Remove-Item $filler -Force -ErrorAction SilentlyContinue
    if ($size -gt 0) { fsutil file createnew $filler $size | Out-Null }
    $size
}
function Fill-Completely {
    $free = (Get-Free)[0]
    Remove-Item $filler -Force -ErrorAction SilentlyContinue
    fsutil file createnew $filler ([Math]::Max(0, $free + 0 - 1MB)) | Out-Null
    $stream = [IO.File]::Open($filler, 'Append', 'Write', 'None')
    try { foreach ($size in 65536, 4096, 512) { $chunk = New-Object byte[] $size; try { while ($true) { $stream.Write($chunk, 0, $size); $stream.Flush($true) } } catch { } } } finally { try { $stream.Dispose() } catch { } }
    (Get-Item $filler).Length
}
function Get-Forwarded {
    $log = Get-WinEvent -ListLog ForwardedEvents
    $newest = Get-WinEvent -LogName ForwardedEvents -MaxEvents 1 -ErrorAction SilentlyContinue
    $oldest = Get-WinEvent -LogName ForwardedEvents -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    @{ records = $log.RecordCount; fileBytes = $log.FileSize; maximumBytes = $log.MaximumSizeInBytes
       newestRecordId = $newest.RecordId; oldestRecordId = $oldest.RecordId }
}
function Sample {
    $free, $total = Get-Free
    $row = [ordered]@{ at = (Now); phase = $script:phase; freeBytes = $free; totalBytes = $total
        fillerBytes = $(if (Test-Path $filler) { (Get-Item $filler).Length } else { 0 })
        destinationBlocked = (Test-Blocked); service = (Get-Service Bower).Status.ToString()
        generatorNext = $(if ($script:generator) { $script:generator.Next } else { $null }) }
    $forwarded = Get-Forwarded
    foreach ($key in $forwarded.Keys) { $row["forwarded" + $key.Substring(0, 1).ToUpper() + $key.Substring(1)] = $forwarded[$key] }
    $status = Get-Status
    if ($status) {
        $subscription = @($status.windowsEventLog)[0]
        $row.health = $status.status; $row.storageState = $status.storage.state; $row.intakePaused = $status.storage.intakePaused
        $row.queueFileBytes = $status.storage.queueFileBytes; $row.pageUtilisation = $status.storage.queuePageUtilisationPercent
        $row.oldestPendingAge = $status.storage.oldestPendingAgeSeconds; $row.storageRefusals = $status.storage.storageRefusals
        $row.pressurePurged = $status.storage.pressurePurgedEvents; $row.capacityRefusals = $status.intake.capacityRefusals
        $row.queued = $status.queue.queued; $row.uploading = $status.queue.uploading; $row.retrying = $status.queue.retrying
        $row.delivered = $status.queue.delivered; $row.deadLettered = $status.queue.deadLettered; $row.undeliveredBytes = $status.queue.undeliveredBytes
        $row.subscriptionState = $subscription.state; $row.bookmarkRecordId = $subscription.bookmarkRecordId
        $row.sourceQueued = $subscription.queued; $row.sourceRetries = $subscription.retries; $row.sourceSubmitFailures = $subscription.submitFailures
        $row.sourceGaps = $subscription.gaps; $row.sourceReadErrors = $subscription.readErrors
    } else { $row.statusError = 'unavailable' }
    [void]$samples.Add($row); Write-Journal ([ordered]@{ kind = 'sample' } + $row); $row
}
function Wait-Until([scriptblock]$condition, [int]$timeout, [string]$label) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        $row = Sample
        if (& $condition $row) { Mark $label @{ met = $true }; return $row }
        Start-Sleep -Seconds 5
    }
    Mark $label @{ met = $false }; $null
}
function Hold([int]$seconds) { $end = (Get-Date).AddSeconds($seconds); while ((Get-Date) -lt $end) { [void](Sample); Start-Sleep 5 } }
function Test-Drained($row) {
    $row.queued -eq 0 -and $row.uploading -eq 0 -and $row.retrying -eq 0 -and $row.intakePaused -eq $false -and
        $row.bookmarkRecordId -ge $row.forwardedNewestRecordId
}

function Reconcile {
    $next = [long](Get-Content "$work\next-seq")
    $key = [Convert]::FromBase64String((Get-Content "$secrets\hmac.key" -Raw).Trim())
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, $key)
    $bySeq = @{}
    for ($seq = 1; $seq -lt $next; $seq++) {
        $name = 'ws3w' + $seq.ToString('D7')
        $hex = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($name)) | ForEach-Object { $_.ToString('x2') })
        $bySeq[$hex] = $name
    }
    Copy-Item 'C:\Program Files\Bower\e_sqlite3.dll' "$work\e_sqlite3.dll" -Force -ErrorAction SilentlyContinue
    [Environment]::CurrentDirectory = $work
    $rows = [Ws3Queue]::Query('Q:\bower\queue.db', "SELECT event_id, json_extract(payload,'$.actor.username'), state, payload_bytes FROM queue_events_v5", 4)
    $queued = @{}; $delivered = 0; $unexpected = 0; $duplicates = 0; $bytes = 0
    foreach ($row in $rows) {
        $bytes += [long]$row[3]
        $hex = if ($row[1]) { ($row[1] -split ':')[-1] } else { $null }
        if ($hex -and $bySeq.ContainsKey($hex)) {
            $name = $bySeq[$hex]
            if ($queued.ContainsKey($name)) { $duplicates++ } else { $queued[$name] = $row[0] }
            if ($row[2] -eq '3') { $delivered++ }
        } else { $unexpected++ }
    }
    $integrity = [Ws3Queue]::Query('Q:\bower\queue.db', 'PRAGMA integrity_check', 1)[0][0]
    $forwardedNames = @{}
    foreach ($event in Get-WinEvent -FilterHashtable @{ LogName = 'ForwardedEvents'; Id = 4625 } -ErrorAction SilentlyContinue) {
        $match = [regex]::Match($event.ToXml(), "<Data Name='TargetUserName'>(ws3w\d{7})</Data>")
        if ($match.Success) { $forwardedNames[$match.Groups[1].Value] = $true }
    }
    $expected = 1..($next - 1) | ForEach-Object { 'ws3w' + ([long]$_).ToString('D7') }
    $missing = @($expected | Where-Object { -not $queued.ContainsKey($_) })
    $notForwarded = @($expected | Where-Object { -not $forwardedNames.ContainsKey($_) })
    $digest = { param($values) $sha = [Security.Cryptography.SHA256]::Create(); -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((($values | Sort-Object) -join "`n"))) | ForEach-Object { $_.ToString('x2') }) }
    [ordered]@{ phase = 'wec-reconcile'; at = (Now); generated = $expected.Count; forwardedIdentities = $forwardedNames.Count
        notForwarded = $notForwarded.Count; notForwardedSample = @($notForwarded | Select-Object -First 20)
        queuedIdentities = $queued.Count; missingFromQueue = $missing.Count; missingSample = @($missing | Select-Object -First 20)
        unexpectedRows = $unexpected; duplicateSequences = $duplicates; deliveredInQueue = $delivered; queueRows = $rows.Count
        averagePayloadBytes = [long]($bytes / [Math]::Max(1, $rows.Count)); sqliteIntegrity = $integrity
        generatedDigest = (& $digest $expected); queuedDigest = (& $digest @($queued.Keys))
        forwarded = (Get-Forwarded) } | ConvertTo-Json -Depth 5 -Compress
}

if ($Scenario -eq 'reconcile') { Reconcile; exit 0 }
if ($Scenario -eq 'probe') { $script:phase = 'probe'; Sample | ConvertTo-Json -Compress; exit 0 }

$script:phase = 'start'; $started = Now
$script:generator = New-Object Ws3Generator($Target, $Rate, "$work\next-seq")
[void](Sample)
$script:generator.Start()
try {
    Mark 'generating' @{ rate = $Rate }
    Hold 30
    Block; Mark 'destination-blocked'
    switch ($Scenario) {
        'queue-cap' {
            [void](Wait-Until { param($r) $r.capacityRefusals -gt 0 -and $r.sourceRetries -gt 0 } $Limit 'queue-cap-refusing')
            Hold $Hold
        }
        'watermarks' {
            $storage = (Get-Status).storage
            $size = Set-Filler ($storage.warningFreeBytes - 32MB); Mark 'filled-below-warning' @{ fillerBytes = $size }
            [void](Wait-Until { param($r) $r.storageState -eq 'warning' } 60 'warning-reported')
            Hold 60
            $size = Set-Filler ($storage.criticalFreeBytes + 24MB); Mark 'filled-near-critical' @{ fillerBytes = $size }
            [void](Wait-Until { param($r) $r.storageState -eq 'critical' } $Limit 'critical-reported')
            Hold $Hold
            Remove-Item $filler -Force; Mark 'space-freed'
            [void](Wait-Until { param($r) $r.storageState -eq 'normal' -and $r.intakePaused -eq $false } 120 'intake-resumed')
            Hold 60
        }
        'disk-full' {
            Hold 30
            $size = Fill-Completely; Mark 'volume-full' @{ fillerBytes = $size; freeBytes = (Get-Free)[0] }
            [void](Wait-Until { param($r) $r.storageState -eq 'critical' } 60 'critical-reported')
            Unblock; Mark 'destination-restored-while-full'
            Hold $Hold
            $restartAt = Get-Date
            Restart-Service Bower -Force -ErrorAction SilentlyContinue; Mark 'service-restarted-while-full'
            $up = Wait-Until { param($r) $r.health } 180 'service-answering-while-full'
            $logged = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.Collector'; StartTime = $restartAt } -ErrorAction SilentlyContinue)
            Mark 'restart-observation' @{ answered = [bool]$up; service = (Get-Service Bower).Status.ToString()
                applicationLogEntries = $logged.Count; applicationLogIds = @($logged | Group-Object Id | ForEach-Object { "$($_.Name)x$($_.Count)" }) }
            Hold 60
            Remove-Item $filler -Force; Mark 'space-freed'
            [void](Wait-Until { param($r) $r.health -and $r.intakePaused -eq $false } 300 'intake-resumed')
            Hold 60
        }
    }
    Unblock; Mark 'destination-restored'
    Hold 120
} finally {
    $script:generator.Stop(); Mark 'generator-stopped' @{ nextSeq = $script:generator.Next; failedBinds = $script:generator.Failed; unexpectedSuccess = $script:generator.Unexpected }
    Unblock; Remove-Item $filler -Force -ErrorAction SilentlyContinue
}
[void](Wait-Until { param($r) Test-Drained $r } 1800 'drained')
$first = { param($predicate) ($samples | Where-Object { & $predicate $_ } | Select-Object -First 1).at }
$summary = [ordered]@{ phase = "wec-$Scenario"; startedAt = $started; endedAt = (Now); events = $events
    generated = @{ firstSeq = $script:generator.First; nextSeq = $script:generator.Next; count = $script:generator.Next - $script:generator.First
        rate = $Rate; maximumLagSeconds = [Math]::Round($script:generator.MaximumLagSeconds, 3); failedBinds = $script:generator.Failed }
    firstWarningAt = (& $first { param($r) $r.storageState -in 'warning', 'critical' })
    firstCriticalAt = (& $first { param($r) $r.storageState -eq 'critical' })
    firstRefusalAt = (& $first { param($r) $r.sourceRetries -gt $samples[0].sourceRetries })
    maximumForwardedLag = ($samples | ForEach-Object { if ($_.bookmarkRecordId) { $_.forwardedNewestRecordId - $_.bookmarkRecordId } else { 0 } } | Measure-Object -Maximum).Maximum
    maximumUndeliveredBytes = ($samples | Measure-Object undeliveredBytes -Maximum).Maximum
    minimumFreeBytes = ($samples | Measure-Object freeBytes -Minimum).Minimum
    maximumQueueFileBytes = ($samples | Measure-Object queueFileBytes -Maximum).Maximum
    sourceGaps = $samples[-1].sourceGaps; sourceSubmitFailures = $samples[-1].sourceSubmitFailures
    samples = $samples.Count; final = $samples[-1] }
$text = $summary | ConvertTo-Json -Depth 6 -Compress
$text | Set-Content -Encoding utf8 "$logs\$Scenario-summary.json"
$text
