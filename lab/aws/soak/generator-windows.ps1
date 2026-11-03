param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][long]$StartEpoch,
    [Parameter(Mandatory=$true)][int]$Seconds,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]{1,40}$')][string]$Label,
    [switch]$Smoke
)
# Soak generator on the domain controller: real NTLM LDAP bind failures against the DC's own
# address, so the DC's Security log is the native 4625 source of truth. Segments start at
# absolute times (no cumulative drift): 10/sec steady and, unless -Smoke, a 60-second
# 100/sec burst at +2 h, +6 h, ... (every 4 hours). Each segment writes one metadata record.
$ErrorActionPreference='Stop'
$address=$null
# 172.31.247.: the 24-hour soak subnet; 172.31.248.: the 72-hour re-soak subnet (lab.py profiles).
if (![Net.IPAddress]::TryParse($Target,[ref]$address) -or -not ($Target.StartsWith('172.31.247.') -or $Target.StartsWith('172.31.248.'))) { throw 'Target must be the lab domain controller' }
if ($Seconds -lt 60 -or $Seconds -gt 266400) { throw 'Seconds out of range' }
Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -ReferencedAssemblies System.DirectoryServices.Protocols,System,System.Core -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading;

public static class BowerNativePilot {
    public static IDictionary<string,object> Run(string target,int rate,int seconds) {
        if(rate<1 || rate>100 || seconds<1 || seconds>14400 || rate*seconds>100000)
            throw new ArgumentOutOfRangeException();
        int count=rate*seconds,completed=0,active=0,maximum=0,successes=0;
        var codes=new ConcurrentDictionary<int,int>();
        var slots=new SemaphoreSlim(64);
        var done=new CountdownEvent(count);
        {
            int minimum,io;ThreadPool.GetMinThreads(out minimum,out io);
            ThreadPool.SetMinThreads(Math.Max(64,minimum),io);
            var clock=Stopwatch.StartNew();
            for(int i=0;i<count;i++) {
                double due=(double)i/rate;
                while(clock.Elapsed.TotalSeconds<due) Thread.Sleep(1);
                slots.Wait();
                ThreadPool.QueueUserWorkItem(delegate(object ignored) {
                    int current=Interlocked.Increment(ref active);
                    int old;
                    do {old=maximum;if(current<=old)break;}
                    while(Interlocked.CompareExchange(ref maximum,current,old)!=old);
                    try {
                        var server=new LdapDirectoryIdentifier(target,389,false,false);
                        using(var connection=new LdapConnection(server)) {
                            connection.AuthType=AuthType.Ntlm;
                            connection.Credential=new NetworkCredential("bower-probe","synthetic-invalid-"+Guid.NewGuid().ToString("N"),"BOWER");
                            connection.Timeout=TimeSpan.FromSeconds(5);
                            try {connection.Bind();Interlocked.Increment(ref successes);}
                            catch(LdapException error) {codes.AddOrUpdate(error.ErrorCode,1,delegate(int key,int n){return n+1;});}
                        }
                    } catch {codes.AddOrUpdate(-1,1,delegate(int key,int n){return n+1;});}
                    finally {Interlocked.Decrement(ref active);Interlocked.Increment(ref completed);slots.Release();done.Signal();}
                });
            }
            bool drained=done.Wait(TimeSpan.FromSeconds(30));
            while(clock.Elapsed.TotalSeconds<seconds)Thread.Sleep(1);
            // A timed-out native call may still complete. Keep its signal objects
            // alive on that failure path instead of throwing from a worker finally.
            if(drained){slots.Dispose();done.Dispose();}
            var resultCodes=new Dictionary<string,int>();
            foreach(var pair in codes) resultCodes.Add(pair.Key.ToString(System.Globalization.CultureInfo.InvariantCulture),pair.Value);
            return new Dictionary<string,object> {
                {"attempted",count},{"completed",completed},{"allCallsCompleted",drained},
                {"seconds",clock.Elapsed.TotalSeconds},{"actualRate",completed/clock.Elapsed.TotalSeconds},
                {"maximumConcurrentCalls",maximum},{"unexpectedSuccessfulLogons",successes},{"ldapResultCodes",resultCodes}
            };
        }
    }
}
'@

function Get-Segments([int]$total, [bool]$smoke) {
    $bursts = @(); if (-not $smoke) { for ($b = 7200; $b + 60 -le $total; $b += 14400) { $bursts += $b } }
    $edges = @(0); foreach ($b in $bursts) { $edges += $b; $edges += $b + 60 }; $edges += $total
    $segments = @()
    for ($i = 0; $i -lt $edges.Count - 1; $i++) {
        $from = $edges[$i]; $to = $edges[$i + 1]; $rate = if ($bursts -contains $from) { 100 } else { 10 }
        # rate*seconds is bounded per native call; steady chunks are at most two hours.
        for ($at = $from; $at -lt $to; $at += 7200) { $segments += ,@($at, [Math]::Min(7200, $to - $at), $rate) }
    }
    return ,$segments
}
$dir = "C:\BowerLab\soak\gen\$Label"
New-Item -ItemType Directory -Force $dir | Out-Null
$segments = Get-Segments $Seconds $Smoke.IsPresent
$n = 0
foreach ($segment in $segments) {
    $n++
    $due = [DateTimeOffset]::FromUnixTimeSeconds($StartEpoch + $segment[0])
    $file = Join-Path $dir ('segment-{0:D3}.json' -f $n)
    if (Test-Path $file) { continue }
    while ([DateTimeOffset]::UtcNow -lt $due) { Start-Sleep -Milliseconds 200 }
    $startedAt = [DateTimeOffset]::UtcNow
    $result = [BowerNativePilot]::Run($Target, [int]$segment[2], [int]$segment[1])
    $result['label'] = $Label; $result['segment'] = $n; $result['offsetSeconds'] = $segment[0]
    $result['rate'] = $segment[2]; $result['plannedSeconds'] = $segment[1]
    $result['scheduledAt'] = $due.ToString('o'); $result['startedAt'] = $startedAt.ToString('o')
    $result['finishedAt'] = [DateTimeOffset]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 4 | Set-Content $file
}
@{ label = $Label; segments = $n; finishedAt = [DateTimeOffset]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content (Join-Path $dir 'done.json')
