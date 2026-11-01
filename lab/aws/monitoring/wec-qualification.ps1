# Invoke through run.py on the owned Windows host. Only synthetic event IDs/counts
# leave the host. No native XML, queue records, certificates or bearer tokens do.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Get-WecQualificationFailure($Failure) {
    $codes = @('source-status-missing', 'event-filter', 'event-count-bound', 'queue-expected-identity',
        'queue-malformed-identity', 'queue-stale-expected-identity', 'queue-duplicate-identity', 'owned-config',
        'action-must-be-phase-diagnostic-cancel-or-snapshot', 'phase-parameters', 'phase-already-exists',
        'synthetic-account-exists', 'existing-loopback-session', 'source-not-running', 'generator-workers-timed-out', 'generator-summary-bound', 'generator-profile', 'generator-warmup-failed', 'warmup-deadline', 'warmup-reconciliation')
    $staticCode = if ($codes -ccontains $Failure.Exception.Message) { $Failure.Exception.Message } else { 'unclassified' }
    $innerType = if ($Failure.Exception.InnerException) { $Failure.Exception.InnerException.GetType().FullName } else { $null }
    $compilerText = $Failure.Exception.Message
    if ($Failure.ErrorDetails) { $compilerText += ' ' + $Failure.ErrorDetails.Message }
    $compilerCodes = @([regex]::Matches($compilerText, '\bCS[0-9]{4}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    return @{ exceptionType = $Failure.Exception.GetType().FullName; innerExceptionType = $innerType;
        hResult = $Failure.Exception.HResult; category = $Failure.CategoryInfo.Category.ToString();
        scriptLine = $(if ($Failure.InvocationInfo) { $Failure.InvocationInfo.ScriptLineNumber } else { 0 });
        staticCode = $staticCode; compilerCodes = $compilerCodes }
}

function Get-WecStatus([ValidateRange(1, 10)][int]$TimeoutSeconds = 10) {
    $token = [IO.File]::ReadAllText('C:\ProgramData\Bower\secrets\ingest-token').Trim()
    try { $status = Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec $TimeoutSeconds }
    finally { $token = $null }
    $source = @($status.windowsEventLog | Where-Object { $_.id -eq 'wec-security' })
    if ($source.Count -ne 1) { throw 'source-status-missing' }
    $source[0] | Add-Member -NotePropertyName queue -NotePropertyValue $status.queue
    $source[0] | Add-Member -NotePropertyName deliveryActivity -NotePropertyValue $status.deliveryActivity
    return $source[0]
}

function Get-WecEventIdentity([string]$Channel, [string]$Account, [DateTimeOffset]$Since, [DateTimeOffset]$Until) {
    if ($Channel -notin @('Security', 'ForwardedEvents') -or $Account -cnotmatch '^bwr[a-f0-9]{17}$' -or $Until -le $Since) { throw 'event-filter' }
    $from = $Since.UtcDateTime.ToString('o')
    $to = $Until.UtcDateTime.ToString('o')
    $xpath = "*[System[(EventID=4625) and TimeCreated[@SystemTime >= '$from' and @SystemTime < '$to']] and EventData[Data[@Name='TargetUserName']='$Account']]"
    $query = New-Object Diagnostics.Eventing.Reader.EventLogQuery($Channel, [Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $reader = New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $invalid = 0
    $firstEvent = $null; $lastEvent = $null
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        while ($null -ne ($record = $reader.ReadEvent())) {
            try {
                if ($ids.Count -ge 50000) { throw 'event-count-bound' }
                [xml]$xml = $record.ToXml()
                $fields = @{}
                foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.InnerText }
                $address = $null
                if ($fields['LogonType'] -ne '3' -or -not [Net.IPAddress]::TryParse($fields['IpAddress'], [ref]$address)) { $invalid++ }
                $created = [DateTimeOffset]::Parse([string]$xml.Event.System.TimeCreated.SystemTime, [Globalization.CultureInfo]::InvariantCulture)
                if ($null -eq $firstEvent -or $created -lt $firstEvent) { $firstEvent = $created }
                if ($null -eq $lastEvent -or $created -gt $lastEvent) { $lastEvent = $created }
                $time = $created.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                # Exactly WindowsEventRecord.EventId: original source XML identity, not the
                # ForwardedEvents receiving bookmark (which is a separate cursor).
                $material = @([string]$xml.Event.System.Channel, [string]$xml.Event.System.Computer,
                    [string]$xml.Event.System.EventRecordID, $time) -join [char]31
                $hex = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))).Replace('-', '').ToLowerInvariant()
                $ids.Add('winevt-' + $hex.Substring(0, 32))
            } finally { $record.Dispose() }
        }
    } finally { $reader.Dispose(); $hash.Dispose() }
    $sorted = @($ids | Sort-Object -Unique)
    $firstText = if ($null -ne $firstEvent) { $firstEvent.ToString('o') } else { $null }
    $lastText = if ($null -ne $lastEvent) { $lastEvent.ToString('o') } else { $null }
    return @{ count = $ids.Count; unique = $sorted.Count; invalidNetworkLogons = $invalid; ids = $sorted;
        firstEventAt = $firstText; lastEventAt = $lastText }
}

function Get-WecObservedRate([long]$Count, [string]$First, [string]$Last) {
    if ($Count -lt 2 -or -not $First -or -not $Last) { return 0.0 }
    $firstAt = [DateTimeOffset]::Parse($First, [Globalization.CultureInfo]::InvariantCulture)
    $lastAt = [DateTimeOffset]::Parse($Last, [Globalization.CultureInfo]::InvariantCulture)
    $span = ($lastAt - $firstAt).TotalSeconds
    if ($span -le 0) { return 0.0 }
    return ($Count - 1) / $span
}

function Get-WecEventWindowEnd([DateTimeOffset]$AttemptsEndedAt) {
    # SMB can return just before its Security audit record obtains its timestamp.
    # Allow exactly five seconds, never an unbounded scan into another phase.
    return $AttemptsEndedAt.AddSeconds(5)
}

function Add-WecQueueReader {
    if ('BowerWecQueueMetadata' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BowerWecQueueMetadata {
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2([MarshalAs(UnmanagedType.LPStr)] string name, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(IntPtr db, [MarshalAs(UnmanagedType.LPStr)] string sql, int length, out IntPtr statement, IntPtr tail);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr statement);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr statement, int column);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_column_bytes(IntPtr statement, int column);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr statement);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_busy_timeout(IntPtr db, int milliseconds);
    public static string[][] Read(string path) {
        IntPtr db=IntPtr.Zero, statement=IntPtr.Zero;
        try {
            // SQLITE_OPEN_READONLY. Never fetch payloads or emit native error text.
            if(sqlite3_open_v2(path,out db,1,IntPtr.Zero)!=0) throw new InvalidOperationException("queue-open");
            if(sqlite3_busy_timeout(db,10000)!=0) throw new InvalidOperationException("queue-timeout");
            const string sql="SELECT event_id, received_at FROM queue_events WHERE event_id LIKE 'winevt-%' LIMIT 200001";
            if(sqlite3_prepare_v2(db,sql,-1,out statement,IntPtr.Zero)!=0) throw new InvalidOperationException("queue-prepare");
            var rows=new List<string[]>();int code;
            while((code=sqlite3_step(statement))==100) {
                if(rows.Count>=200000 || sqlite3_column_bytes(statement,0)>128 || sqlite3_column_bytes(statement,1)>64)
                    throw new InvalidOperationException("queue-bound");
                rows.Add(new string[] {Marshal.PtrToStringAnsi(sqlite3_column_text(statement,0)),Marshal.PtrToStringAnsi(sqlite3_column_text(statement,1))});
            }
            if(code!=101) throw new InvalidOperationException("queue-read");
            return rows.ToArray();
        } finally {if(statement!=IntPtr.Zero)sqlite3_finalize(statement);if(db!=IntPtr.Zero)sqlite3_close(db);}
    }
}
'@
}

function Select-WecQueueIdentity($Rows, [string[]]$Expected, [DateTimeOffset]$Since, [DateTimeOffset]$Until) {
    $expectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($identity in $Expected) { if ($identity -cnotmatch '^winevt-[a-f0-9]{32}$' -or -not $expectedSet.Add($identity)) { throw 'queue-expected-identity' } }
    $accepted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($row in $Rows) {
        if ($row.Count -ne 2 -or $row[0] -cnotmatch '^winevt-[a-f0-9]{32}$') { throw 'queue-malformed-identity' }
        $received = [DateTimeOffset]::Parse($row[1], [Globalization.CultureInfo]::InvariantCulture)
        $inside = $received -ge $Since -and $received -le $Until
        if ($expectedSet.Contains($row[0]) -and -not $inside) { throw 'queue-stale-expected-identity' }
        if ($inside -and -not $accepted.Add($row[0])) { throw 'queue-duplicate-identity' }
    }
    return ,([string[]]@($accepted | Sort-Object))
}

function Write-WecGeneratorCheckpoint([string]$Path, [string]$RunId, [string]$Phase, [string]$Mode, $Generator) {
    $report = [ordered]@{ recordType = 'generator-checkpoint'; runId = $RunId; phase = $Phase; mode = $Mode;
        generator = $Generator; nativeVerified = $false; destinationQueryVerified = $false; deliveryQualified = $false }
    $json = $report | ConvertTo-Json -Depth 8 -Compress
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json + "`n")
    if ($bytes.Length -gt 32768) { throw 'generator-summary-bound' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Write-Output $json
}

function Complete-WecWarmup([string]$Root, [string]$Phase, [string]$Account, $Before, $Metadata) {
    $report = [ordered]@{ kind = 'native-warmup'; generator = $Metadata; warmupVerified = $false;
        measuredQualification = $false; destinationQueryVerified = $false; deliveryQualified = $false }
    $prefix = Join-Path $Root ($Phase + '-warmup')
    $path = $prefix + '.json'
    # Retain bounded attempt metadata even if native reconciliation cannot finish.
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    try {
        $since = [DateTimeOffset]::Parse([string]$Metadata.startedAt)
        $until = Get-WecEventWindowEnd ([DateTimeOffset]::Parse([string]$Metadata.endedAt))
        $deadline = [DateTimeOffset]::Parse([string]$Metadata.deadlineAt)
        while ([DateTimeOffset]::UtcNow -lt $until) {
            if ([DateTimeOffset]::UtcNow -ge $deadline) { throw 'warmup-deadline' }
            Start-Sleep -Milliseconds 100
        }
        do {
            if ([DateTimeOffset]::UtcNow -ge $deadline) { throw 'warmup-deadline' }
            $native = Get-WecEventIdentity Security $Account $since $until
            $forwarded = Get-WecEventIdentity ForwardedEvents $Account $since $until
            $remaining = [int][Math]::Floor(($deadline - [DateTimeOffset]::UtcNow).TotalSeconds)
            if ($remaining -lt 1) { throw 'warmup-deadline' }
            $after = Get-WecStatus -TimeoutSeconds ([Math]::Min(3, $remaining))
            $accepted = [long]$after.queued - [long]$Before.queued
            $same = ($native.ids -join "`n") -ceq ($forwarded.ids -join "`n")
            $ready = $native.count -gt 0 -and $native.unique -eq $native.count -and $native.invalidNetworkLogons -eq 0 -and
                $forwarded.count -eq $native.count -and $forwarded.unique -eq $native.unique -and $forwarded.invalidNetworkLogons -eq 0 -and
                $same -and $accepted -eq $native.count -and $after.state -eq 'running'
            $report.native = @{ count = $native.count; unique = $native.unique; invalidNetworkLogons = $native.invalidNetworkLogons }
            $report.forwarded = @{ count = $forwarded.count; unique = $forwarded.unique; invalidNetworkLogons = $forwarded.invalidNetworkLogons }
            $report.acceptedDelta = $accepted
            if ($ready) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        foreach ($counter in 'rejected', 'parserErrors', 'malformed', 'oversized', 'gaps', 'resets', 'cursorConflicts') {
            if ($after.$counter -ne $Before.$counter) { $ready = $false }
        }
        [IO.File]::WriteAllLines(($prefix + '-native.ids'), [string[]]$native.ids, [Text.Encoding]::ASCII)
        [IO.File]::WriteAllLines(($prefix + '-forwarded.ids'), [string[]]$forwarded.ids, [Text.Encoding]::ASCII)
        Add-WecQueueReader
        $queueIds = Select-WecQueueIdentity ([BowerWecQueueMetadata]::Read('C:\ProgramData\Bower\data\bower.db')) ([string[]]$native.ids) $since ([DateTimeOffset]::UtcNow)
        [IO.File]::WriteAllLines(($prefix + '-queue.ids'), [string[]]$queueIds, [Text.Encoding]::ASCII)
        $queueSame = ($native.ids -join "`n") -ceq ($queueIds -join "`n")
        $report.queue = @{ count = $queueIds.Count; exactNativeMatch = $queueSame }
        $report.eventWindowEndedAt = $until.ToString('o')
        $report.completedAt = [DateTimeOffset]::UtcNow.ToString('o')
        $report.warmupVerified = [bool]($ready -and $queueSame -and [DateTimeOffset]::UtcNow -le $deadline)
        $report.identities = @('native', 'forwarded', 'queue') | ForEach-Object {
            @{ kind = $_; sha256 = (Get-FileHash ($prefix + '-' + $_ + '.ids')).Hash.ToLowerInvariant() }
        }
        if (-not $report.warmupVerified) { throw 'warmup-reconciliation' }
        $Metadata['nativeCount'] = $native.count
        $Metadata['forwardedCount'] = $forwarded.count
        $Metadata['queueCount'] = $queueIds.Count
        $Metadata['nativeIdsSha256'] = (Get-FileHash ($prefix + '-native.ids')).Hash.ToLowerInvariant()
        $Metadata['forwardedIdsSha256'] = (Get-FileHash ($prefix + '-forwarded.ids')).Hash.ToLowerInvariant()
        $Metadata['queueIdsSha256'] = (Get-FileHash ($prefix + '-queue.ids')).Hash.ToLowerInvariant()
        $Metadata['completedAt'] = $report.completedAt
        return $after
    } catch {
        $report.failure = Get-WecQualificationFailure $_
        throw
    } finally {
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
        # Explicit host path only; no event XML or credential material is serialized.
    }
}

function Add-WecGenerator {
    if ('BowerWecNetworkGenerator' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
public interface IBowerWecNetworkNative {
    IntPtr CreateToken(string account, string password);
    void Impersonate(IntPtr token);
    int Connect(string account, string password, bool explicitCredentials);
    int Cancel();
    bool Revert();
    bool Close(IntPtr token);
}
public sealed class BowerWecWindowsNative : IBowerWecNetworkNative {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Resource { public int scope, type, display, usage; public string local, remote, comment, provider; }
    [DllImport("mpr.dll", CharSet=CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref Resource resource, string password, string username, int flags);
    [DllImport("mpr.dll", CharSet=CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool LogonUser(string username, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    public IntPtr CreateToken(string account, string password) {
        IntPtr token;
        if(!LogonUser(account,Environment.MachineName,password,9,3,out token))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return token;
    }
    public void Impersonate(IntPtr token) {
        if(!ImpersonateLoggedOnUser(token))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    public int Connect(string account, string password, bool explicitCredentials) {
        var resource=new Resource {type=0,remote=@"\\127.0.0.1\IPC$"};
        return WNetAddConnection2(ref resource,explicitCredentials?password:null,
            explicitCredentials?Environment.MachineName+@"\"+account:null,4);
    }
    public int Cancel() {return WNetCancelConnection2(@"\\127.0.0.1\IPC$",0,true);}
    public bool Revert() {return RevertToSelf();}
    public bool Close(IntPtr token) {return CloseHandle(token);}
}
public static class BowerWecNetworkGenerator {
    public static IDictionary<string,object> Run(string account,int rate,int seconds,string cancel,string profile,bool warmup,Action<object> reconcileWarmup) {
        return RunWithNative(account,rate,seconds,cancel,profile,new BowerWecWindowsNative(),30000,warmup,reconcileWarmup);
    }
    // Dependency injection exercises scheduling/accounting without producing fake host evidence.
    // Only Run above is invoked by the host harness; no backend can be selected by environment.
    public static IDictionary<string,object> RunWithNative(string account,int rate,int seconds,string cancel,
        string profile,IBowerWecNetworkNative native,int waitMilliseconds) {
        return RunWithNative(account,rate,seconds,cancel,profile,native,waitMilliseconds,false,null);
    }
    public static IDictionary<string,object> RunWithNative(string account,int rate,int seconds,string cancel,
        string profile,IBowerWecNetworkNative native,int waitMilliseconds,bool warmup,Action<object> reconcileWarmup) {
        if(rate<1 || rate>100 || seconds<1 || seconds>3600 || rate*seconds>50000 ||
           !Regex.IsMatch(account,"^bwr[a-f0-9]{17}$") || native==null || waitMilliseconds<1 || waitMilliseconds>30000 ||
           (profile!="phase-explicit" && profile!="worker-explicit" && profile!="worker-null") ||
           (warmup && (profile=="worker-null" || reconcileWarmup==null)))throw new ArgumentOutOfRangeException();
        bool shared=profile=="phase-explicit", explicitCredentials=profile!="worker-null", isolated=profile=="worker-explicit";
        int requested=rate*seconds,workers=Math.Min(isolated?4:64,requested),scheduled=0,completed=0,succeeded=0,active=0,maximum=0;
        int setupFailures=0,impersonationFailures=0,revertFailures=0,closeFailures=0,cleanupFailures=0,remaining=workers;
        int warmScheduled=0,warmCompleted=0,warmActive=0,warmMaximum=0,warmSucceeded=0;
        long lastMeasuredCompletion=0;
        var warmCodes=new ConcurrentDictionary<int,int>();
        var codes=new ConcurrentDictionary<int,int>();var sessionCodes=new ConcurrentDictionary<int,int>();
        var cleanupCodes=new ConcurrentDictionary<int,int>();var reasons=new ConcurrentDictionary<string,int>();
        var work=new BlockingCollection<int>(64);var ready=new CountdownEvent(workers);var done=new CountdownEvent(workers);
        var start=new ManualResetEventSlim(false);
        var connectionsDone=new CountdownEvent(workers);var cleanupGate=new object();
        var workerQueues=new BlockingCollection<int>[workers];
        if(isolated)for(int i=0;i<workers;i++)workerQueues[i]=new BlockingCollection<int>(1);
        Func<int,int,bool> enqueue=delegate(int item,int timeout) {
            return (isolated?workerQueues[(item<0?-item-1:item)%workers]:work).TryAdd(item,timeout);
        };
        // Each phase or worker owns its network logon LUID; credentials remain stable.
        // Explicit repeated credentials avoid null-credential ambiguity and per-call password collisions.
        string password="synthetic-invalid-"+Guid.NewGuid().ToString("N");
        var phaseToken=new Lazy<IntPtr>(delegate(){return native.CreateToken(account,password);},true);
        Action<Exception,string> failureCode=delegate(Exception failure,string stage) {
            reasons.AddOrUpdate(stage,1,delegate(string k,int v){return v+1;});
            var win32=failure as System.ComponentModel.Win32Exception;
            if(win32!=null)sessionCodes.AddOrUpdate(win32.NativeErrorCode,1,delegate(int k,int v){return v+1;});
        };
        Action<IntPtr,bool,bool> finish=delegate(IntPtr token,bool impersonated,bool last) {
            bool cleanup=!shared || last;
            if(shared && last && phaseToken.IsValueCreated)token=phaseToken.Value;
            // Cleanup is confined to the owned LUID, after its worker(s) finish.
            // Never cancel any connection in the caller's logon session.
            if(cleanup && token!=IntPtr.Zero) {
                try {
                    if(!impersonated){native.Impersonate(token);impersonated=true;}
                    int code=native.Cancel();cleanupCodes.AddOrUpdate(code,1,delegate(int k,int v){return v+1;});
                    if(code!=0 && code!=2250)Interlocked.Increment(ref cleanupFailures);
                } catch {Interlocked.Increment(ref cleanupFailures);}
            }
            if(impersonated && !native.Revert())Interlocked.Increment(ref revertFailures);
            if(cleanup && token!=IntPtr.Zero && !native.Close(token))Interlocked.Increment(ref closeFailures);
        };
        for(int worker=0;worker<workers;worker++) {
            var workerWork=isolated?workerQueues[worker]:work;
            var thread=new Thread(delegate() {
                IntPtr token=IntPtr.Zero;bool impersonated=false,announced=false;
                try {
                    try {token=shared?phaseToken.Value:native.CreateToken(account,password);}
                    catch(Exception failure){Interlocked.Increment(ref setupFailures);failureCode(failure,"logon-token");return;}
                    try {native.Impersonate(token);impersonated=true;}
                    catch(Exception failure){Interlocked.Increment(ref impersonationFailures);failureCode(failure,"impersonation");return;}
                    ready.Signal();announced=true;start.Wait();
                    foreach(int item in workerWork.GetConsumingEnumerable()) {
                        bool preparing=item<0;
                        int current=preparing?Interlocked.Increment(ref warmActive):Interlocked.Increment(ref active),old;
                        if(preparing) {
                            do {old=warmMaximum;if(current<=old)break;} while(Interlocked.CompareExchange(ref warmMaximum,current,old)!=old);
                        } else {
                            do {old=maximum;if(current<=old)break;} while(Interlocked.CompareExchange(ref maximum,current,old)!=old);
                        }
                        var target=preparing?warmCodes:codes;
                        try {
                            int code=native.Connect(account,password,explicitCredentials);
                            target.AddOrUpdate(code,1,delegate(int k,int v){return v+1;});
                            if(code==0){if(preparing)Interlocked.Increment(ref warmSucceeded);else Interlocked.Increment(ref succeeded);}
                        } catch {target.AddOrUpdate(-1,1,delegate(int k,int v){return v+1;});}
                        finally {
                            if(preparing){Interlocked.Decrement(ref warmActive);Interlocked.Increment(ref warmCompleted);}
                            else {
                                    long stamp=DateTimeOffset.UtcNow.UtcDateTime.Ticks,previous;
                                    do {previous=Interlocked.Read(ref lastMeasuredCompletion);if(stamp<=previous)break;}
                                    while(Interlocked.CompareExchange(ref lastMeasuredCompletion,stamp,previous)!=previous);
                                    Interlocked.Decrement(ref active);Interlocked.Increment(ref completed);
                                }
                        }
                    }
                } catch(Exception failure){Interlocked.Increment(ref setupFailures);failureCode(failure,"worker-exception");}
                finally {
                    if(!announced)ready.Signal();
                    bool last=Interlocked.Decrement(ref remaining)==0;
                    try {
                        if(isolated) {
                            connectionsDone.Signal();connectionsDone.Wait();
                            lock(cleanupGate){finish(token,impersonated,last);}
                        } else finish(token,impersonated,last);
                    }catch{Interlocked.Increment(ref cleanupFailures);}
                    done.Signal();
                }
            });
            thread.IsBackground=true;
            try {thread.Start();}
            catch(Exception failure) {
                Interlocked.Increment(ref setupFailures);failureCode(failure,"worker-start");ready.Signal();
                if(isolated)connectionsDone.Signal();
                bool last=Interlocked.Decrement(ref remaining)==0;
                try {finish(IntPtr.Zero,false,last);}catch{Interlocked.Increment(ref cleanupFailures);}
                done.Signal();
            }
        }
        bool initialized=ready.Wait(waitMilliseconds);
        if(!initialized)reasons.AddOrUpdate("ready-timeout",1,delegate(string k,int v){return v+1;});
        start.Set();
        bool warmupVerified=!warmup;
        IDictionary<string,object> warmupSummary=null;
        if(warmup && initialized && setupFailures==0 && impersonationFailures==0) {
            var preparation=Stopwatch.StartNew();var warmBegin=DateTimeOffset.UtcNow;
            // Exactly 100 preparatory calls at 10/s, bounded by a 30-second total
            // preparation budget. They are never part of measured counters/rate.
            for(int i=0;i<100;i++) {
                while(preparation.Elapsed.TotalSeconds<(double)i/10 && !File.Exists(cancel))Thread.Sleep(1);
                if(File.Exists(cancel) || preparation.Elapsed.TotalSeconds>=30 || !enqueue(-i-1,Math.Min(100,waitMilliseconds)))break;
                warmScheduled++;
            }
            while(Volatile.Read(ref warmCompleted)<warmScheduled && preparation.Elapsed.TotalSeconds<30 && !File.Exists(cancel))Thread.Sleep(5);
            var warmEnd=DateTimeOffset.UtcNow;
            var warmResults=new Dictionary<string,int>();foreach(var pair in warmCodes)warmResults.Add(pair.Key.ToString(),pair.Value);
            warmupSummary=new Dictionary<string,object> {
                {"kind","native-warmup"},{"requested",100},{"requestedRate",10},{"scheduled",warmScheduled},{"completed",warmCompleted},
                {"unexpectedSuccesses",warmSucceeded},{"maxConcurrency",warmMaximum},{"resultCodes",warmResults},
                {"startedAt",warmBegin.ToString("o")},{"endedAt",warmEnd.ToString("o")},{"deadlineAt",warmBegin.AddSeconds(30).ToString("o")},
                {"drained",warmCompleted==warmScheduled},{"activeAtReturn",warmActive},{"totalBudgetSeconds",30}
            };
            if(warmScheduled==100 && warmCompleted==100 && warmSucceeded==0 && !File.Exists(cancel) && !warmCodes.ContainsKey(1219) && !warmCodes.ContainsKey(-1)) {
                try {reconcileWarmup(warmupSummary);warmupVerified=preparation.Elapsed.TotalSeconds<=30;}
                catch {reasons.AddOrUpdate("warmup-evidence",1,delegate(string k,int v){return v+1;});}
            }
            if(!warmupVerified)reasons.AddOrUpdate("warmup-not-verified",1,delegate(string k,int v){return v+1;});
        }
        var clock=Stopwatch.StartNew();var beganAt=DateTimeOffset.UtcNow;string began=beganAt.ToString("o");
        if(initialized && setupFailures==0 && impersonationFailures==0 && warmupVerified) {
            for(int i=0;i<requested;i++) {
                while(clock.Elapsed.TotalSeconds<(double)i/rate && !File.Exists(cancel))Thread.Sleep(1);
                if(File.Exists(cancel) || !enqueue(i,Math.Min(5000,waitMilliseconds)))break;
                scheduled++;
            }
        }
        if(isolated){foreach(var queue in workerQueues)queue.CompleteAdding();}else work.CompleteAdding();
        bool connectionsDrained=isolated?connectionsDone.Wait(waitMilliseconds):false;
        double elapsed=0;string ended=null;
        if(isolated) {
            while(clock.Elapsed.TotalSeconds<seconds && !File.Exists(cancel) && scheduled==requested && connectionsDrained)Thread.Sleep(1);
            elapsed=connectionsDrained && completed==requested
                ?Math.Max(seconds,(Interlocked.Read(ref lastMeasuredCompletion)-beganAt.UtcDateTime.Ticks)/(double)TimeSpan.TicksPerSecond)
                :clock.Elapsed.TotalSeconds;
            ended=beganAt.AddSeconds(elapsed).ToString("o");
        }
        bool drained=done.Wait(waitMilliseconds);
        if(!isolated) {
            while(clock.Elapsed.TotalSeconds<seconds && !File.Exists(cancel) && scheduled==requested && drained)Thread.Sleep(1);
            elapsed=clock.Elapsed.TotalSeconds;ended=DateTimeOffset.UtcNow.ToString("o");
        }
        var resultCodes=new Dictionary<string,int>();foreach(var pair in codes)resultCodes.Add(pair.Key.ToString(),pair.Value);
        var setupCodes=new Dictionary<string,int>();foreach(var pair in sessionCodes)setupCodes.Add(pair.Key.ToString(),pair.Value);
        var finalCleanupCodes=new Dictionary<string,int>();foreach(var pair in cleanupCodes)finalCleanupCodes.Add(pair.Key.ToString(),pair.Value);
        var initializationReasons=new Dictionary<string,int>();foreach(var pair in reasons)initializationReasons.Add(pair.Key,pair.Value);
        return new Dictionary<string,object> {
            {"executionKind",native is BowerWecWindowsNative?"native-windows":"simulated"},
            {"warmupRequired",warmup},{"warmupVerified",warmupVerified},{"warmup",warmupSummary},
            {"initializationFailureReasons",initializationReasons},{"requested",requested},{"scheduled",scheduled},{"completed",completed},
            {"unexpectedSuccesses",succeeded},{"drained",drained},{"cancelled",File.Exists(cancel)},{"seconds",elapsed},
            {"actualRate",elapsed>0?completed/elapsed:0},{"maxConcurrency",maximum},{"workerCount",workers},{"resultCodes",resultCodes},
            {"credentialIsolation",shared?"per-phase-logon-new-credentials":"per-worker-logon-new-credentials"},
            {"credentialMode",explicitCredentials?"explicit-stable-per-phase":"implicit-token"},{"initialized",initialized},
            {"sessionSetupFailures",setupFailures},{"impersonationFailures",impersonationFailures},{"revertFailures",revertFailures},
            {"handleCloseFailures",closeFailures},{"sessionResultCodes",setupCodes},{"sessionCleanupFailures",cleanupFailures},
            {"sessionCleanupCodes",finalCleanupCodes},{"activeAtReturn",active},{"workersRemainingAtReturn",done.CurrentCount},
            {"startedAt",began},{"endedAt",ended}
        };
    }
}
'@
}

$lock = $null
$result = $null
$step = 'parameters'
try {
    $root = 'C:\ProgramData\Bower\monitoring'
    $config = Get-Content "$root\qualification.json" -Raw | ConvertFrom-Json
    if ($env:OS -ne 'Windows_NT' -or $env:BOWER_LAB_RUN -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or
        $config.runId -cne $env:BOWER_LAB_RUN -or $config.accountName -cnotmatch '^bwr[a-f0-9]{17}$') { throw 'owned-config' }
    $action = $env:BOWER_WEC_ACTION
    if ($action -eq 'cancel') { [IO.File]::WriteAllText("$root\cancel", 'cancel'); Write-Output '{"cancelRequested":true}'; exit 0 }
    if ($action -eq 'snapshot') {
        @{ runId = $config.runId; at = [DateTimeOffset]::UtcNow.ToString('o'); source = (Get-WecStatus);
            destinationQueryVerified = $false; deliveryQualified = $false } | ConvertTo-Json -Depth 8 -Compress
        exit 0
    }
    if ($action -notin @('phase', 'diagnostic')) { throw 'action-must-be-phase-diagnostic-cancel-or-snapshot' }
    $diagnostic = $action -eq 'diagnostic'
    $generatorProfile = $env:BOWER_WEC_PROFILE
    if (-not $generatorProfile) { $generatorProfile = 'phase-explicit' }
    if ($generatorProfile -notin @('phase-explicit', 'worker-explicit', 'worker-null') -or (-not $diagnostic -and $generatorProfile -eq 'worker-null')) { throw 'generator-profile' }
    $phase = $env:BOWER_WEC_PHASE
    [int]$rate = 0; [int]$seconds = 0
    if ($diagnostic) { $env:BOWER_WEC_RATE = '1'; $env:BOWER_WEC_SECONDS = '1' }
    if ($phase -cnotmatch '^[a-z][a-z0-9-]{0,39}$' -or
        -not [int]::TryParse($env:BOWER_WEC_RATE, [ref]$rate) -or ($rate -notin @(10, 100) -and -not ($diagnostic -and $rate -eq 1)) -or
        -not [int]::TryParse($env:BOWER_WEC_SECONDS, [ref]$seconds) -or $seconds -lt 1 -or $seconds -gt 3600 -or
        $rate * $seconds -gt 50000) { throw 'phase-parameters' }
    $lock = [IO.File]::Open("$root\generator.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    if ((Test-Path "$root\$phase.json") -or (Test-Path "$root\$phase-generator.json") -or (Test-Path "$root\$phase-warmup.json")) { throw 'phase-already-exists' }
    if (Get-LocalUser -Name $config.accountName -ErrorAction SilentlyContinue) { throw 'synthetic-account-exists' }
    # Avoid reusing an authenticated loopback SMB session, which would invalidate native proof.
    if (Get-SmbConnection | Where-Object { $_.ServerName -in @('127.0.0.1', 'localhost', $env:COMPUTERNAME) }) { throw 'existing-loopback-session' }
    Remove-Item "$root\cancel" -ErrorAction SilentlyContinue
    $step = 'source-before'
    $before = Get-WecStatus
    if ($before.state -ne 'running') { throw 'source-not-running' }
    $step = 'generator-compile'
    Add-WecGenerator
    $step = 'generator-execute'
    $sourceBeforeWarmup = $before
    $warmupCallback = [Action[object]] { param($metadata)
        $script:before = Complete-WecWarmup $root $phase $config.accountName $sourceBeforeWarmup $metadata
    }
    $result = [BowerWecNetworkGenerator]::Run($config.accountName, $rate, $seconds, "$root\cancel", $generatorProfile, (-not $diagnostic), $warmupCallback)
    Write-WecGeneratorCheckpoint "$root\$phase-generator.json" $config.runId $phase $action $result
    $step = 'generator-timing'
    $since = [DateTimeOffset]::Parse([string]$result.startedAt, [Globalization.CultureInfo]::InvariantCulture)
    $until = [DateTimeOffset]::Parse([string]$result.endedAt, [Globalization.CultureInfo]::InvariantCulture)
    $eventUntil = Get-WecEventWindowEnd $until
    $report = [ordered]@{ runId = $config.runId; phase = $phase; requestedRate = $rate;
        mode = $action; startedAt = $since.ToString('o'); endedAt = $until.ToString('o'); generator = $result;
        eventWindowEndedAt = $eventUntil.ToString('o'); eventWindowPaddingSeconds = 5;
        sourceBefore = $before; nativeVerified = $false; destinationQueryVerified = $false; deliveryQualified = $false }
    # Persist bounded generator evidence before inspecting event channels, including failed runs.
    $report | ConvertTo-Json -Depth 8 | Set-Content "$root\$phase.json" -Encoding UTF8
    if (-not $result.drained) { throw 'generator-workers-timed-out' }
    if (-not $diagnostic -and -not $result.warmupVerified) { throw 'generator-warmup-failed' }
    while ([DateTimeOffset]::UtcNow -lt $eventUntil) { Start-Sleep -Milliseconds 100 }
    $step = 'native-reconciliation'
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($(if ($diagnostic) { 30 } else { 180 }))
    do {
        $native = Get-WecEventIdentity Security $config.accountName $since $eventUntil
        $forwarded = Get-WecEventIdentity ForwardedEvents $config.accountName $since $eventUntil
        $after = Get-WecStatus
        if ($native.count -eq $result.completed -and $forwarded.count -eq $native.count -and
            $after.queued - $before.queued -ge $native.count) { break }
        Start-Sleep -Seconds 5
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    [IO.File]::WriteAllLines("$root\$phase-native.ids", [string[]]$native.ids, [Text.Encoding]::ASCII)
    [IO.File]::WriteAllLines("$root\$phase-forwarded.ids", [string[]]$forwarded.ids, [Text.Encoding]::ASCII)
    $same = ($native.ids -join "`n") -ceq ($forwarded.ids -join "`n")
    $accepted = [long]$after.queued - [long]$before.queued
    $step = 'durable-queue-identities'
    Add-WecQueueReader
    $queueRows = [BowerWecQueueMetadata]::Read('C:\ProgramData\Bower\data\bower.db')
    $queueIds = Select-WecQueueIdentity $queueRows ([string[]]$native.ids) $since ([DateTimeOffset]::UtcNow)
    [IO.File]::WriteAllLines("$root\$phase-queue.ids", [string[]]$queueIds, [Text.Encoding]::ASCII)
    $queueSame = ($native.ids -join "`n") -ceq ($queueIds -join "`n")
    $report.queueIdentities = @{ count = $queueIds.Count; exactNativeMatch = $queueSame;
        idsSha256 = (Get-FileHash "$root\$phase-queue.ids").Hash.ToLowerInvariant() }
    $observedRate = Get-WecObservedRate $native.count $native.firstEventAt $native.lastEventAt
    $report.native = @{ firstEventAt = $native.firstEventAt; lastEventAt = $native.lastEventAt; observedRate = $observedRate;
        count = $native.count; unique = $native.unique; invalidNetworkLogons = $native.invalidNetworkLogons;
        idsSha256 = (Get-FileHash "$root\$phase-native.ids").Hash.ToLowerInvariant() }
    $report.forwarded = @{ count = $forwarded.count; unique = $forwarded.unique; invalidNetworkLogons = $forwarded.invalidNetworkLogons;
        idsSha256 = (Get-FileHash "$root\$phase-forwarded.ids").Hash.ToLowerInvariant() }
    $report.sourceAfter = $after
    $report.acceptedDelta = $accepted
    $report.diagnosticNativeMatched = [bool]($diagnostic -and $result.requested -eq 1 -and $result.completed -eq 1 -and
        $result.drained -and $result.initialized -and -not $result.cancelled -and $result.unexpectedSuccesses -eq 0 -and
        $result.sessionSetupFailures -eq 0 -and $result.impersonationFailures -eq 0 -and $result.revertFailures -eq 0 -and
        $result.handleCloseFailures -eq 0 -and $result.sessionCleanupFailures -eq 0 -and
        $native.count -eq 1 -and $native.unique -eq 1 -and $native.invalidNetworkLogons -eq 0 -and $same -and $queueSame -and $accepted -eq 1)
    $report.nativeVerified = (-not $diagnostic -and $result.scheduled -eq $result.requested -and $result.completed -eq $result.requested -and
        $result.unexpectedSuccesses -eq 0 -and -not $result.cancelled -and $result.actualRate -ge $rate * 0.99 -and
        $result.initialized -and $result.sessionSetupFailures -eq 0 -and $result.impersonationFailures -eq 0 -and
        $result.revertFailures -eq 0 -and $result.handleCloseFailures -eq 0 -and $result.sessionCleanupFailures -eq 0 -and $observedRate -ge $rate * 0.99 -and
        -not $result.resultCodes.ContainsKey('1219') -and
        $native.count -eq $result.requested -and $native.unique -eq $native.count -and $native.invalidNetworkLogons -eq 0 -and
        $forwarded.count -eq $native.count -and $forwarded.unique -eq $native.unique -and $same -and $queueSame -and $accepted -eq $native.count -and
        $after.state -eq 'running')
    foreach ($counter in 'rejected', 'parserErrors', 'malformed', 'oversized', 'gaps', 'resets', 'cursorConflicts') {
        if ($after.$counter -ne $before.$counter) { $report.nativeVerified = $false }
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content "$root\$phase.json" -Encoding UTF8
    $report | ConvertTo-Json -Depth 8 -Compress
    if (-not $report.nativeVerified -and -not $report.diagnosticNativeMatched) { exit 1 }
} catch {
    @{ qualification = 'failed'; step = $step; failure = (Get-WecQualificationFailure $_); generator = $result; destinationQueryVerified = $false; deliveryQualified = $false } | ConvertTo-Json -Depth 4 -Compress
    exit 1
}
finally { if ($lock) { $lock.Dispose() } }
