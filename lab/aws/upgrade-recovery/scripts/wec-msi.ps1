$ErrorActionPreference = 'Stop'
# MSI install/upgrade/downgrade attempt under load; metadata only.
$msi = 'C:\BowerLab\artifacts\{{MSI}}'
if (!(Test-Path $msi)) { & 'C:\Program Files\Amazon\AWSCLIV2\aws.exe' s3 cp 's3://{{Artifacts}}/artifacts/{{MSI}}' $msi --region '{{REGION}}' --only-show-errors }
$before = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
$svc = Get-CimInstance Win32_Service -Filter "Name='Bower'"
$envBefore = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment | ForEach-Object { ($_ -split '=',2)[0] })
$start = [DateTimeOffset]::UtcNow
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart {{PROPS}} /l*v C:\BowerLab\msi-{{LABEL}}.log" -Wait -PassThru
$end = [DateTimeOffset]::UtcNow
$healthy = $null
for ($i = 0; $i -lt 60; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; $healthy = [DateTimeOffset]::UtcNow; break } catch { Start-Sleep -Seconds 1 } }
$after = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
$svc2 = Get-CimInstance Win32_Service -Filter "Name='Bower'"
$envAfter = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment | ForEach-Object { ($_ -split '=',2)[0] })
$log = Get-Content "C:\BowerLab\msi-{{LABEL}}.log" -ErrorAction SilentlyContinue
$downgrade = [bool]($log | Select-String -SimpleMatch 'A newer Bower Collector is already installed' -Quiet)
[ordered]@{ label = '{{LABEL}}'; msi = '{{MSI}}'; exitCode = $p.ExitCode; before = $before; after = $after; startedAt = $start.ToString('o'); finishedAt = $end.ToString('o')
  msiSeconds = [Math]::Round(($end - $start).TotalSeconds, 2); healthyAfterSeconds = $(if ($healthy) { [Math]::Round(($healthy - $end).TotalSeconds, 2) } else { $null })
  pidBefore = $svc.ProcessId; pidAfter = $svc2.ProcessId; state = $svc2.State; account = $svc2.StartName
  envNamesBefore = $envBefore.Count; envNamesAfter = $envAfter.Count; envNamesLost = @($envBefore | Where-Object { $envAfter -notcontains $_ }); envNamesAdded = @($envAfter | Where-Object { $envBefore -notcontains $_ })
  downgradeMessageLogged = $downgrade } | ConvertTo-Json -Depth 4
