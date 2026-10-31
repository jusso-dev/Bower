$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# v1 -> v2 bookmark upgrade on a local Security subscription. Lab-only process (SYSTEM via a
# scheduled task, loopback status port, no output); the queue never leaves the host.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$phase = '{{PHASE}}'
$t = 'C:\BowerLab\v1test'
New-Item -ItemType Directory -Force "$t\state","$t\no-defaults","$t\snap" | Out-Null
function Fetch($name, $path) { if (!(Test-Path $path)) { & $aws s3 cp "s3://{{Artifacts}}/$name" $path --region '{{REGION}}' --only-show-errors; if ($LASTEXITCODE -ne 0) { throw "download $name" } } }
Fetch 'artifacts/legacy-74e250f-win-x64.zip' "$t\legacy.zip"
Fetch 'artifacts/new.msi' "$t\new.msi"
Fetch 'artifacts/probe-win-x64.zip' "$t\probe.zip"
Fetch 'artifacts/windows-security-logon-1.0.2.bowerpack' "$t\windows.bowerpack"
Fetch 'artifacts/bower-signing.pub.pem' "$t\trusted.pem"
if (!(Test-Path "$t\legacy\Bower.Collector.exe")) { Expand-Archive "$t\legacy.zip" -DestinationPath "$t\legacy" -Force }
if (!(Test-Path "$t\probe\Bower.LabProbe.exe")) { Expand-Archive "$t\probe.zip" -DestinationPath "$t\probe" -Force }
if (!(Test-Path "$t\msi270\Bower\Bower.Collector.exe")) {
    $p = Start-Process msiexec.exe -ArgumentList "/a `"$t\new.msi`" /qn TARGETDIR=`"$t\msi270`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "admin extract failed $($p.ExitCode)" }
}
if (!(Test-Path "$t\token")) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    foreach ($n in 'token','hmac.key') { $b = New-Object byte[] 48; $rng.GetBytes($b); [IO.File]::WriteAllText("$t\$n", [Convert]::ToBase64String($b)) }
    icacls $t /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
}
'{"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[{"id":"wec-security","channel":"Security","eventIds":[4625],"providers":["Microsoft-Windows-Security-Auditing"],"pack":"windows-security-logon","parser":0,"readExisting":true,"pollIntervalSeconds":1,"batchSize":256}]}' | Set-Content "$t\wel.json" -Encoding ASCII
$exe = if ('{{BIN}}' -eq 'legacy') { "$t\legacy\Bower.Collector.exe" } else { (Get-ChildItem "$t\msi270" -Recurse -Filter Bower.Collector.exe | Select-Object -First 1).FullName }
$envs = @{ BOWER_LISTEN_URL='http://127.0.0.1:4329'; BOWER_INGEST_TOKEN_FILE="$t\token"; BOWER_QUEUE_PATH="$t\state\queue.db";
  BOWER_POLICY_DIRECTORY="$t\no-defaults"; BOWER_COLLECTOR_ID='dc-v1test'; BOWER_ENVIRONMENT='validation'; BOWER_OUTPUT='none';
  BOWER_PACKS="$t\windows.bowerpack"; BOWER_PACK_TRUSTED_KEYS="$t\trusted.pem"; BOWER_PRIVACY_HMAC_KEY_FILE="$t\hmac.key";
  BOWER_WINDOWS_EVENTLOG_CONFIG="$t\wel.json"; BOWER_AMA_SPOOL_PATH="$t\spool" }
$psi = New-Object Diagnostics.ProcessStartInfo $exe
$psi.UseShellExecute = $false; $psi.WorkingDirectory = Split-Path $exe
foreach ($k in $envs.Keys) { $psi.EnvironmentVariables[$k] = $envs[$k] }
$started = [DateTimeOffset]::UtcNow
$proc = [Diagnostics.Process]::Start($psi)
$token = [IO.File]::ReadAllText("$t\token")
$samples = @()
$deadline = (Get-Date).AddSeconds({{SECONDS}})
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    try { $s = Invoke-RestMethod 'http://127.0.0.1:4329/v1/status' -Headers @{Authorization="Bearer $token"} -TimeoutSec 5; $w = $s.windowsEventLog | Select-Object -First 1
          $samples += [ordered]@{ at=[DateTimeOffset]::UtcNow.ToString('o'); state=$w.state; eventsRead=$w.eventsRead; queued=$w.queued; duplicates=$w.duplicates; resets=$w.resets; gaps=$w.gaps; bookmark=$w.bookmarkRecordId; readErrors=$w.readErrors } } catch { $samples += [ordered]@{ at=[DateTimeOffset]::UtcNow.ToString('o'); error=$_.Exception.GetType().Name } }
}
Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 2
& "$t\probe\Bower.LabProbe.exe" queue "$t\state\queue.db" "$t\snap\$phase-queue.json"
& "$t\probe\Bower.LabProbe.exe" native Security '{{SINCE}}' "$t\snap\$phase-native.json"
$r = [ordered]@{ phase=$phase; exe=$exe; exeSha256=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant(); startedAt=$started.ToString('o'); stoppedAt=[DateTimeOffset]::UtcNow.ToString('o')
  samples=$samples; queue=(Get-Content "$t\snap\$phase-queue.json" -Raw | ConvertFrom-Json); native=(Get-Content "$t\snap\$phase-native.json" -Raw | ConvertFrom-Json)
  securityLog=[ordered]@{ records=(Get-WinEvent -ListLog Security).RecordCount } }
$r | ConvertTo-Json -Depth 6 | Set-Content "$t\snap\$phase.json" -Encoding UTF8
foreach ($f in Get-ChildItem "$t\snap" -Filter "$phase*") { & $aws s3 cp $f.FullName "s3://{{Artifacts}}/results/BOWERDC/v1test-$($f.Name)" --region '{{REGION}}' --only-show-errors }
$last = $samples[-1]
[ordered]@{ phase=$phase; last=$last; q=$r.queue.queued; del=$r.queue.delivered; total=$r.queue.total; cursors=$r.queue.cursors; nativeDistinct=$r.native.distinct; securityRecords=$r.securityLog.records } | ConvertTo-Json -Depth 5 -Compress
