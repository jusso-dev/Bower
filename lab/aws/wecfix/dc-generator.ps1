$ErrorActionPreference = 'Stop'
# Registers and starts the measured 10/s generator (100/s for 60 s at +2 h) as a SYSTEM task.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$dir = 'C:\BowerLab\wecfix'
New-Item -ItemType Directory -Force $dir | Out-Null
& $aws s3 cp 's3://{{Artifacts}}/artifacts/wecfix/generator-windows.ps1' "$dir\generator-windows.ps1" --region '{{REGION}}' --only-show-errors
if ((Get-FileHash "$dir\generator-windows.ps1" -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{GEN_SHA256}}') { throw 'generator digest mismatch' }
$name = 'BowerWecfixGen-{{LABEL}}'
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'label already used' }
$arg = "-NoProfile -ExecutionPolicy Bypass -File $dir\generator-windows.ps1 -Target {{DcIp}} -StartEpoch {{START}} -Seconds {{SECONDS}} -Label {{LABEL}}"
Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)) `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg) `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6)) | Out-Null
Start-ScheduledTask -TaskName $name
Write-Output "generator $name start={{START}} seconds={{SECONDS}}"
