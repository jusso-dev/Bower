# Replaces the collector binaries and health check with the bucket's current build; keeps the
# queue, configuration and secrets. Prints hashes only.
$ErrorActionPreference = 'Stop'
$stage = Join-Path $env:TEMP 'bower-upgrade'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key 'artifacts/windows/collector.zip' -File "$stage\collector.zip" -Region $env:AWS_DEFAULT_REGION | Out-Null
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key 'artifacts/windows/Test-BowerCollectorHealth.ps1' -File 'C:\ProgramData\Bower\monitoring\Test-BowerCollectorHealth.ps1' -Region $env:AWS_DEFAULT_REGION | Out-Null
Expand-Archive -Path "$stage\collector.zip" -DestinationPath $stage -Force
Stop-Service Bower -Force
Remove-Item 'C:\Program Files\Bower\*' -Recurse -Force
Copy-Item "$stage\collector-win-x64\*" 'C:\Program Files\Bower' -Recurse -Force
& icacls.exe 'C:\Program Files\Bower' /reset /T /Q | Out-Null
Remove-Item $stage -Recurse -Force
Start-Service Bower
for ($i = 0; $i -lt 30; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep 1 } }
"upgraded $([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) $((Get-Service Bower).Status)"
(Get-FileHash 'C:\Program Files\Bower\Bower.Collector.dll').Hash
(Get-FileHash 'C:\ProgramData\Bower\monitoring\Test-BowerCollectorHealth.ps1').Hash
