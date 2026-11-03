$ErrorActionPreference = 'Stop'
# Sets BOWER_QUEUE_RETENTION_HOURS so each hourly retention run purges tens of thousands of
# acknowledged rows inside the measured window, then restarts the service.
$path = 'C:\ProgramData\Bower\bower.env'
$lines = Get-Content $path | Where-Object { $_ -notmatch '^BOWER_QUEUE_RETENTION_HOURS=' }
$lines += 'BOWER_QUEUE_RETENTION_HOURS={{HOURS}}'
Set-Content $path $lines -Encoding ASCII
Restart-Service Bower
for ($i = 0; $i -lt 60; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 2 } }
Write-Output ("{0} retentionHours={{HOURS}} service={1}" -f $env:COMPUTERNAME, (Get-Service Bower).Status)
