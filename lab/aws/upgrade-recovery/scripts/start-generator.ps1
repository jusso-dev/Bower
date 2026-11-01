$ErrorActionPreference='Stop'
$aws='C:\Program Files\Amazon\AWSCLIV2\aws.exe'
& $aws s3 cp 's3://{{Artifacts}}/artifacts/generator.ps1' C:\BowerLab\generator.ps1 --region '{{REGION}}' --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'download failed' }
$name='BowerGen-{{LABEL}}'
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'generator label already used' }
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\BowerLab\generator.ps1 -Target {{DcIp}} -Rate {{RATE}} -Seconds {{SECONDS}} -Label {{LABEL}}"
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 5) -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName $name -Action $action -User 'SYSTEM' -RunLevel Highest -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $name
Start-Sleep -Seconds 3
Get-Content "C:\BowerLab\gen\{{LABEL}}.json" -ErrorAction SilentlyContinue
Write-Output "started $name rate={{RATE}} seconds={{SECONDS}}"
