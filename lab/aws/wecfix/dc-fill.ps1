$ErrorActionPreference = 'Stop'
# Pre-fill: real 4625 events (local network logons with an unknown user and a random
# password) as fast as the DC allows, so ForwardedEvents on both WECs reaches the target
# record count quickly. The user is 'bower-fill' so the fill is told apart from the
# measured 'bower-probe' load. Writes one metadata record; never prints credentials.
$count = [int]'{{COUNT}}'
$threads = [int]'{{THREADS}}'
if ($count -lt 1 -or $count -gt 2000000 -or $threads -lt 1 -or $threads -gt 32) { throw 'out of range' }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class BowerFill {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static long[] Run(int count, int threads) {
        long done = 0, unexpected = 0;
        var workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            workers[t] = new Thread(() => {
                while (Interlocked.Increment(ref done) <= count) {
                    IntPtr token;
                    if (LogonUserW("bower-fill", "BOWER", "synthetic-invalid-" + Guid.NewGuid().ToString("N"), 3, 0, out token)) {
                        Interlocked.Increment(ref unexpected); CloseHandle(token);
                    }
                }
            });
            workers[t].Start();
        }
        foreach (var w in workers) w.Join();
        return new long[] { count, unexpected };
    }
}
'@
$started = [DateTimeOffset]::UtcNow
$result = [BowerFill]::Run($count, $threads)
$finished = [DateTimeOffset]::UtcNow
$log = Get-WinEvent -ListLog Security
[ordered]@{
    attempted = $result[0]; unexpectedSuccessfulLogons = $result[1]
    seconds = ($finished - $started).TotalSeconds; rate = $result[0] / ($finished - $started).TotalSeconds
    startedAt = $started.ToString('o'); finishedAt = $finished.ToString('o')
    securityRecordCount = $log.RecordCount; securityFileSize = $log.FileSize
} | ConvertTo-Json -Compress
