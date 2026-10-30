param(
    [Parameter(Mandatory=$true)][DateTimeOffset]$StartAt,
    [Parameter(Mandatory=$true)][ValidatePattern('^bower-pilot-\d{8}-\d{6}$')][string]$RunId
)
$ErrorActionPreference='Stop'
$root='C:\BowerLab\pilot'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$service=Get-CimInstance Win32_Service -Filter "Name='Bower'"
if ($service.StartName -ne 'NT SERVICE\Bower') {throw 'Unexpected collector account'}
$rule='Bower pilot outage '+$RunId
if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) {throw 'Outage rule already exists'}
$headers=@{Authorization='Bearer '+[IO.File]::ReadAllText('C:\ProgramData\Bower\secrets\token')}
$samples=New-Object 'System.Collections.Generic.List[object]'
$blockAt=$StartAt.AddSeconds(658)
$restoreAt=$StartAt.AddSeconds(4265)
$endAt=$StartAt.AddSeconds(4890)
$blocked=$false
$restored=$null
$outageStarted=$null
$drained=$null
$backlogAtRestore=$null
$failure=$null
$previousCpu=$null
$previousAt=$null
$initialAccepted=$null
if ([DateTimeOffset]::UtcNow -gt $StartAt.AddSeconds(2)) {throw 'Scheduled start is already stale'}
while ([DateTimeOffset]::UtcNow -lt $StartAt) {Start-Sleep -Milliseconds 100}
try {
 while ([DateTimeOffset]::UtcNow -lt $endAt) {
  $now=[DateTimeOffset]::UtcNow
  if (!$blocked -and $null -eq $restored -and $now -ge $blockAt) {
   New-NetFirewallRule -DisplayName $rule -Direction Outbound -Program 'C:\Program Files\Bower\Bower.Collector.exe' -Protocol TCP -RemotePort 443 -Action Block | Out-Null
   $blocked=$true
   $outageStarted=[DateTimeOffset]::UtcNow
  }
  $s=Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers $headers -TimeoutSec 10
  $accepted=$s.queue.queued+$s.queue.retrying+$s.queue.uploading+$s.queue.delivered+$s.queue.deadLettered
  $pending=$accepted-$s.queue.delivered
  if ($null -eq $initialAccepted) {$initialAccepted=$accepted}
  if ($blocked -and $now -ge $restoreAt) {
   $backlogAtRestore=$pending
   Remove-NetFirewallRule -DisplayName $rule
   $blocked=$false
   $restored=[DateTimeOffset]::UtcNow
  }
  if ($null -ne $restored -and $null -eq $drained) {
   if ($null -eq $s.queue.oldestUndelivered -or [DateTimeOffset]::Parse($s.queue.oldestUndelivered) -ge $restored) {
    $drained=[DateTimeOffset]::UtcNow
   }
  }
  $process=Get-Process -Name Bower.Collector
  $cpu=0
  if ($null -ne $previousCpu) {$cpu=100*($process.CPU-$previousCpu)/($now-$previousAt).TotalSeconds}
  $previousCpu=$process.CPU;$previousAt=$now
  $disk=New-Object IO.DriveInfo('C:\')
  $bytes=(Get-ChildItem 'C:\ProgramData\Bower\state\queue.db*' | Measure-Object Length -Sum).Sum
  $phase=if ($blocked) {'outage'} elseif ($null -ne $restored) {'drain-with-live-traffic'} elseif ($now -ge $StartAt.AddSeconds(600)) {'burst'} else {'steady'}
  $record=@([math]::Round(($now-$StartAt).TotalSeconds,2),$phase,$accepted,$pending,$s.queue.deadLettered,[math]::Round($cpu,2),$process.WorkingSet64,$disk.AvailableFreeSpace,$bytes)
  $samples.Add($record)
  @{runId=$RunId;utc=$now.ToString('o');sample=$record;serviceId=$process.Id} | ConvertTo-Json -Compress | Set-Content "$root\monitor-progress.json"
  if ($disk.AvailableFreeSpace -lt 536870912) {throw 'Low free disk; stopping qualification'}
  Start-Sleep -Seconds 5
 }
} catch {
 $failure=$_.Exception.GetType().Name
} finally {
 if ($blocked) {Remove-NetFirewallRule -DisplayName $rule}
}
$outageSeconds=if ($null -ne $restored -and $null -ne $outageStarted) {($restored-$outageStarted).TotalSeconds} else {0}
$drainSeconds=if ($null -ne $drained) {($drained-$restored).TotalSeconds} else {$null}
$checks=@{completed=($null -eq $failure);outageAtLeastOneHour=($outageSeconds -ge 3600);backlogRetained=($backlogAtRestore -ge 41400);backlogDrainedWithinTenMinutes=($null -ne $drainSeconds -and $drainSeconds -le 600);noDeadLetters=(@($samples | Where-Object {$_[4] -ne 0}).Count -eq 0);noPendingAtEnd=($samples.Count -gt 0 -and $samples[$samples.Count-1][3] -eq 0)}
$kept=@();for ($i=0;$i -lt $samples.Count;$i+=12) {$kept+=,@($samples[$i])}
if ($samples.Count) {$kept+=,@($samples[$samples.Count-1])}
$report=@{phase='native-wec-pilot';runId=$RunId;startedAt=$StartAt.ToString('o');endedAt=[DateTimeOffset]::UtcNow.ToString('o');outageSeconds=$outageSeconds;backlogAtRestore=$backlogAtRestore;drainSeconds=$drainSeconds;initialAccepted=$initialAccepted;failureType=$failure;checks=$checks;passed=(@($checks.Values | Where-Object {!$_}).Count -eq 0);peakCollectorCpuPercentOfOneCore=($samples | ForEach-Object {$_[5]} | Measure-Object -Maximum).Maximum;peakCollectorResidentBytes=($samples | ForEach-Object {$_[6]} | Measure-Object -Maximum).Maximum;minimumFreeDiskBytes=($samples | ForEach-Object {$_[7]} | Measure-Object -Minimum).Minimum;maximumDbWalBytes=($samples | ForEach-Object {$_[8]} | Measure-Object -Maximum).Maximum;sampleColumns=@('elapsedSeconds','phase','accepted','pending','deadLetters','cpuPercentOfOneCore','rssBytes','freeDiskBytes','dbWalBytes');samples=$kept}
$report | ConvertTo-Json -Depth 8 -Compress | Tee-Object -FilePath "$root\monitor-result.json"
