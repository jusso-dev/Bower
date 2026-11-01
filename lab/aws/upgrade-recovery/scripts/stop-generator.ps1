$ErrorActionPreference="Stop"
Stop-ScheduledTask -TaskName BowerGen-w-main2
Start-Sleep 2
[ordered]@{stoppedAt=[DateTimeOffset]::UtcNow.ToString("o");state=(Get-ScheduledTask -TaskName BowerGen-w-main2).State.ToString()} | ConvertTo-Json -Compress
