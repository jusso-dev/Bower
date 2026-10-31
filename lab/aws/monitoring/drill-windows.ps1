# Fault injection on the drill's Windows WEC collector host. $env:DRILL_ACTION selects one step;
# each prints the UTC time it took effect. Metadata only.
$ErrorActionPreference = 'Stop'
function Now { [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
switch ($env:DRILL_ACTION) {
    'disable-wec' { & wecutil.exe ss bower-forwarded /e:false; "fault $(Now) WEC subscription disabled" }
    'enable-wec' { & wecutil.exe ss bower-forwarded /e:true; "recovered $(Now) WEC subscription enabled" }
    'stop-generator' { Stop-ScheduledTask -TaskName BowerDrillGenerator; Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*generator.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "fault $(Now) generator stopped" }
    'start-generator' { Start-ScheduledTask -TaskName BowerDrillGenerator; "recovered $(Now) generator started" }
    'stop-service' { Stop-Service Bower -Force; "fault $(Now) Bower service stopped" }
    'start-service' { Start-Service Bower; "recovered $(Now) Bower service started" }
    'kill-service' {
        $process = Get-Process Bower.Collector; Stop-Process -Id $process.Id -Force; "fault $(Now) killed $($process.Id)"
        for ($i = 0; $i -lt 120; $i++) {
            Start-Sleep -Milliseconds 500
            try { Invoke-RestMethod -Uri 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; "recovered $(Now) service recovery restarted the collector"; break } catch { }
        }
    }
    'healthcheck' {
        Start-ScheduledTask -TaskName BowerHealthCheck; Start-Sleep -Seconds 15
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.HealthCheck' } -MaxEvents ([int]($env:DRILL_LINES, 5 -ne $null)[0]) -ErrorAction SilentlyContinue |
            ForEach-Object { '{0:o} {1} {2}' -f $_.TimeCreated.ToUniversalTime(), $_.Id, $_.Message }
    }
    'collector-events' {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.Collector'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 10 -ErrorAction SilentlyContinue |
            ForEach-Object { '{0:o} {1} {2}' -f $_.TimeCreated.ToUniversalTime(), $_.Id, ($_.Message -replace '\s+', ' ') }
    }
    'status' { }
    default { throw 'unknown action' }
}
& wecutil.exe gr bower-forwarded | Select-String '^\s*(RunTimeStatus|LastError)' | ForEach-Object { 'wec ' + $_.Line.Trim() }
try {
    $token = (Get-Content 'C:\ProgramData\Bower\secrets\ingest-token' -Raw).Trim()
    $status = Invoke-RestMethod -Uri 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 5
    [ordered]@{ status = $status.status; queue = $status.queue; windowsEventLog = @($status.windowsEventLog | Select-Object id, state, eventsRead, queued, readErrors, lastEventAt); sources = @($status.sources | Select-Object application, state, silentSeconds) } | ConvertTo-Json -Depth 4 -Compress
} catch { 'collector status unavailable' }
