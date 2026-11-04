$ErrorActionPreference = 'Stop'
# Extra load to reach soak-level retained queue rows quickly: RATE/sec real NTLM LDAP bind
# failures for SECONDS, on top of the running 10/s generator, as a SYSTEM task. Uses the
# generator's own BowerNativePilot type, so events are identical in shape and user.
$dir = 'C:\BowerLab\wecfix'
$script = @"
`$ErrorActionPreference = 'Stop'
`$source = Get-Content '$dir\generator-windows.ps1' -Raw
`$code = [regex]::Match(`$source, "(?s)-TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -ReferencedAssemblies System.DirectoryServices.Protocols,System,System.Core -TypeDefinition `$code
`$started = [DateTimeOffset]::UtcNow
`$r = [BowerNativePilot]::Run('{{DcIp}}', {{RATE}}, {{SECONDS}})
`$r['label'] = '{{LABEL}}'; `$r['startedAt'] = `$started.ToString('o'); `$r['finishedAt'] = [DateTimeOffset]::UtcNow.ToString('o')
`$r | ConvertTo-Json -Depth 4 | Set-Content '$dir\burst-{{LABEL}}.json'
"@
Set-Content "$dir\burst-{{LABEL}}.ps1" $script
$name = 'BowerWecfixBurst-{{LABEL}}'
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'label already used' }
Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)) `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $dir\burst-{{LABEL}}.ps1") `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)) | Out-Null
Start-ScheduledTask -TaskName $name
"burst $name rate={{RATE}} seconds={{SECONDS}}"
