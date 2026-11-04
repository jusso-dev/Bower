$ErrorActionPreference = 'Stop'
# In-place MSI upgrade to the wecfix build under load (operator settings, queue and bookmarks
# are kept). Metadata only.
$msi = 'C:\BowerLab\artifacts\collector-{{BUILD}}.msi'
& 'C:\Program Files\Amazon\AWSCLIV2\aws.exe' s3 cp 's3://{{Artifacts}}/artifacts/wecfix/{{BUILD}}/collector.msi' $msi --region '{{REGION}}' --only-show-errors
if ((Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{MSI_SHA256}}') { throw 'msi digest mismatch' }
$before = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
$pidBefore = (Get-CimInstance Win32_Service -Filter "Name='Bower'").ProcessId
$start = [DateTimeOffset]::UtcNow
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /l*v C:\BowerLab\msi-{{BUILD}}.log" -Wait -PassThru
$end = [DateTimeOffset]::UtcNow
$healthy = $null
for ($i = 0; $i -lt 90; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; $healthy = [DateTimeOffset]::UtcNow; break } catch { Start-Sleep -Seconds 1 } }
$svc = Get-CimInstance Win32_Service -Filter "Name='Bower'"
[ordered]@{ build = '{{BUILD}}'; exitCode = $p.ExitCode; before = $before
  after = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
  startedAt = $start.ToString('o'); finishedAt = $end.ToString('o'); healthyAt = $(if ($healthy) { $healthy.ToString('o') } else { $null })
  pidBefore = $pidBefore; pidAfter = $svc.ProcessId; state = $svc.State; account = $svc.StartName
  collectorSha256 = (Get-FileHash 'C:\Program Files\Bower\Bower.Collector.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
  settingsSha256 = (Get-FileHash 'C:\ProgramData\Bower\bower.env' -Algorithm SHA256).Hash.ToLowerInvariant() } | ConvertTo-Json
