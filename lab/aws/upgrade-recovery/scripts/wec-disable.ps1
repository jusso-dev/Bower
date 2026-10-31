$ErrorActionPreference="Stop"
Stop-Service Bower
Set-Service Bower -StartupType Disabled
[ordered]@{at=[DateTimeOffset]::UtcNow.ToString("o");state=(Get-Service Bower).Status.ToString()} | ConvertTo-Json -Compress
