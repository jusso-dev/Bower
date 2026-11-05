$ErrorActionPreference = 'Stop'
# Re-soak in-guest expiry guard (Wec, Dc): a SYSTEM task shuts the host down at GUARD_AT (epoch,
# UTC). The instance's shutdown behaviour is terminate, so this ends the host even if nobody
# returns and the stack's scheduler guard fails. StartWhenAvailable runs a missed trigger after a
# reboot. Rendered by lab.py.  ACTION=install|status
$Action = '{{ACTION}}'; $run = '{{RUN_ID}}'
if ($run -cnotmatch '^bower-resoak-[0-9]{8}-[0-9]{6}$') { throw 'not an owned re-soak host' }
$name = 'BowerResoakExpiry'
if ($Action -eq 'install') {
    $at = [DateTimeOffset]::FromUnixTimeSeconds([long]'{{GUARD_AT}}')
    if ($at -lt [DateTimeOffset]::UtcNow.AddHours(1)) { throw 'guard time must be at least an hour ahead' }
    Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest -Force `
        -Trigger (New-ScheduledTaskTrigger -Once -At $at.LocalDateTime) `
        -Action (New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/s /f /t 0 /d p:0:0 /c "Bower re-soak expiry guard"') `
        -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)) | Out-Null
}
$task = Get-ScheduledTask -TaskName $name
$info = Get-ScheduledTaskInfo -TaskName $name
[ordered]@{ guard = 'scheduled-task'; state = "$($task.State)"; at = $task.Triggers[0].StartBoundary
    next = if ($info.NextRunTime) { $info.NextRunTime.ToUniversalTime().ToString('o') } else { $null }; shutdownBehaviour = 'terminate' } | ConvertTo-Json -Compress
