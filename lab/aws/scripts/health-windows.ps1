$ErrorActionPreference='Stop'
$os=Get-CimInstance Win32_OperatingSystem
$health=$null
for ($attempt=0;$attempt -lt 60;$attempt++) {
    try {$health=Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2;break} catch {Start-Sleep -Seconds 2}
}
$service=Get-CimInstance Win32_Service -Filter "Name='Bower'"
$process=if ($service.ProcessId) {Get-Process -Id $service.ProcessId} else {$null}
[pscustomobject]@{phase='post-reboot';host=$env:BOWER_LAB_HOST;bootTime=([DateTimeOffset]$os.LastBootUpTime).ToUnixTimeSeconds();health=if ($health) {$health.status} else {'unreachable'};service=$service.State;bootToProcessSeconds=if ($process) {($process.StartTime-$os.LastBootUpTime).TotalSeconds}else{$null};usedMemoryPercent=[math]::Round((1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,1)} | ConvertTo-Json -Compress
if (-not $health) {exit 1}
