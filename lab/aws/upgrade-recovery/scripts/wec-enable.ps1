$ErrorActionPreference="Stop"
Set-Service Bower -StartupType Automatic
Start-Service Bower
Start-Sleep 45
[ordered]@{at=[DateTimeOffset]::UtcNow.ToString("o");state=(Get-Service Bower).Status.ToString()} | ConvertTo-Json -Compress
