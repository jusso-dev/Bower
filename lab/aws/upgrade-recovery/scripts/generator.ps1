param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][int]$Rate,
    [Parameter(Mandatory=$true)][int]$Seconds,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]{1,40}$')][string]$Label
)
$ErrorActionPreference='Stop'
$address=$null
if (![Net.IPAddress]::TryParse($Target,[ref]$address) -or !$Target.StartsWith('172.31.244.')) { throw 'Target must be the lab domain controller' }
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
New-Item -ItemType Directory -Force C:\BowerLab\gen | Out-Null
$startedAt=[DateTimeOffset]::UtcNow
@{label=$Label;startedAt=$startedAt.ToString('o');state='running'} | ConvertTo-Json | Set-Content "C:\BowerLab\gen\$Label.json"
$result=[BowerNativePilot]::Run($Target,$Rate,$Seconds)
$result['label']=$Label
$result['startedAt']=$startedAt.ToString('o')
$result['finishedAt']=[DateTimeOffset]::UtcNow.ToString('o')
$result['state']='finished'
$result | ConvertTo-Json -Depth 4 | Set-Content "C:\BowerLab\gen\$Label.json"
