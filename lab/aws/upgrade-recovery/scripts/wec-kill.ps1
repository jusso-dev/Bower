$ErrorActionPreference = 'Stop'
if ('{{UNBLOCK}}' -eq 'yes') { Get-NetFirewallRule -DisplayName 'Bower lab destination outage' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Start-Sleep -Seconds {{DELAY}} }
$pid0 = (Get-CimInstance Win32_Service -Filter "Name='Bower'").ProcessId
$killed = [DateTimeOffset]::UtcNow
taskkill.exe /F /PID $pid0 | Out-Null
$healthy = $null; $pid1 = $null
for ($i = 0; $i -lt 120; $i++) { $pid1 = (Get-CimInstance Win32_Service -Filter "Name='Bower'").ProcessId; if ($pid1 -and $pid1 -ne $pid0) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; $healthy = [DateTimeOffset]::UtcNow; break } catch {} }; Start-Sleep -Milliseconds 500 }
[ordered]@{ label='{{LABEL}}'; killedPid=$pid0; newPid=$pid1; killedAt=$killed.ToString('o'); healthyAt=$(if ($healthy) { $healthy.ToString('o') } else { $null }); recoverySeconds=$(if ($healthy) { [Math]::Round(($healthy-$killed).TotalSeconds,2) } else { $null }); unblocked='{{UNBLOCK}}' } | ConvertTo-Json -Compress
