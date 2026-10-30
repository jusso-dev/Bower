param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][DateTimeOffset]$StartAt,
    [Parameter(Mandatory=$true)][ValidatePattern('^bower-pilot-\d{8}-\d{6}$')][string]$RunId,
    [switch]$Preflight
)
$ErrorActionPreference='Stop'
$address=$null
if (![Net.IPAddress]::TryParse($Target,[ref]$address) -or !$Target.StartsWith('172.31.240.')) {
    throw 'Target must be the recorded private pilot domain-controller address'
}
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
        if(rate<1 || rate>100 || seconds<1 || seconds>3600 || rate*seconds>50000)
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
if ($Preflight) {
    $result=[BowerNativePilot]::Run($Target,100,10)
    $result['phase']='native-windows-generator-preflight'
    $result['runId']=$RunId
    $result | ConvertTo-Json -Depth 6 -Compress
    if (!$result['allCallsCompleted'] -or $result['unexpectedSuccessfulLogons'] -ne 0 -or
        $result['completed'] -ne 1000 -or $result['actualRate'] -lt 99 -or
        @($result['ldapResultCodes'].Keys | Where-Object { $_ -ne 49 }).Count -ne 0) {
        throw 'Native generator preflight failed'
    }
    return
}
$root='C:\BowerLab\pilot'
New-Item -ItemType Directory -Path $root -Force | Out-Null
if ([DateTimeOffset]::UtcNow -gt $StartAt.AddSeconds(2)) {throw 'Scheduled start is already stale'}
while ([DateTimeOffset]::UtcNow -lt $StartAt) {Start-Sleep -Milliseconds 100}
$phases=@()
$plans=@(@('steady',10,600),@('burst',100,60),@('outage-burst',100,60),@('outage-steady',10,3540),@('drain-with-live-traffic',10,600))
foreach ($plan in $plans) {
    @{runId=$RunId;phase=$plan[0];startedAt=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json -Compress | Set-Content "$root\generator-progress.json"
    $result=[BowerNativePilot]::Run($Target,[int]$plan[1],[int]$plan[2])
    $result['name']=$plan[0]
    $result['targetRate']=[int]$plan[1]
    $phases+=,$result
    $phases | ConvertTo-Json -Depth 6 | Set-Content "$root\generator-phases.json"
    if (!$result['allCallsCompleted'] -or $result['unexpectedSuccessfulLogons'] -ne 0 -or
        $result['completed'] -ne $result['attempted'] -or
        @($result['ldapResultCodes'].Keys | Where-Object { $_ -ne 49 }).Count -ne 0 -or
        $result['actualRate'] -lt ([int]$plan[1] * 0.99)) {
        throw 'Native authentication generator failed; inspect metadata-only progress'
    }
}
$report=@{phase='native-windows-generator';runId=$RunId;startedAt=$StartAt.ToString('o');endedAt=[DateTimeOffset]::UtcNow.ToString('o');phases=$phases}
$report | ConvertTo-Json -Depth 8 -Compress | Tee-Object -FilePath "$root\generator-result.json"
