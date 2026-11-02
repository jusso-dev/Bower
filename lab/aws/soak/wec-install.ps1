$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Soak WEC: the CI-built MSI from main, operator settings in %ProgramData%\Bower\bower.env,
# the signed Windows pack, ForwardedEvents 4 GiB and the per-minute host health check.
# Credentials are fetched on-host from the owned bucket and never printed.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$prefix = 's3://{{Artifacts}}/artifacts/soak/wec'
New-Item -ItemType Directory -Force C:\BowerLab\artifacts | Out-Null
function Fetch($name, $path) {
    & $aws s3 cp "$prefix/$name" $path --region '{{REGION}}' --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "download failed: $name" }
}
foreach ($f in 'collector.msi', 'windows-security-logon-1.0.2.bowerpack', 'pack-signing.pub.pem', 'Test-BowerCollectorHealth.ps1', 'manifest.json') {
    Fetch $f "C:\BowerLab\artifacts\$f"
}
$manifest = Get-Content C:\BowerLab\artifacts\manifest.json -Raw | ConvertFrom-Json
foreach ($f in 'collector.msi', 'windows-security-logon-1.0.2.bowerpack', 'pack-signing.pub.pem', 'Test-BowerCollectorHealth.ps1') {
    if ((Get-FileHash "C:\BowerLab\artifacts\$f" -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.$f) { throw "digest mismatch: $f" }
}
if (Get-Service Bower -ErrorAction SilentlyContinue) { throw 'Bower is already installed on this host' }
$install = Start-Process msiexec.exe -ArgumentList '/i C:\BowerLab\artifacts\collector.msi /qn /norestart COLLECTORID={{RUN_ID}}-windows BOWERENVIRONMENT=lab /l*v C:\BowerLab\install.log' -Wait -PassThru
if ($install.ExitCode -notin @(0, 3010)) { throw "MSI failed: $($install.ExitCode)" }
Stop-Service Bower
$root = 'C:\ProgramData\Bower'
New-Item -ItemType Directory -Force "$root\monitoring", "$root\packs", "$root\keys", "$root\no-defaults" | Out-Null
Copy-Item C:\BowerLab\artifacts\windows-security-logon-1.0.2.bowerpack "$root\packs\windows.bowerpack"
Copy-Item C:\BowerLab\artifacts\pack-signing.pub.pem "$root\keys\pack-signing.pub.pem"
Copy-Item C:\BowerLab\artifacts\Test-BowerCollectorHealth.ps1 "$root\monitoring\Test-BowerCollectorHealth.ps1"
Fetch 'ingest.pem' "$root\secrets\ingest.pem"
Fetch 'hmac.key' "$root\secrets\hmac.key"
Fetch 'ingest-token' "$root\secrets\token"
Fetch 'sentinel.json' C:\BowerLab\sentinel.json
$s = Get-Content C:\BowerLab\sentinel.json -Raw | ConvertFrom-Json
Remove-Item C:\BowerLab\sentinel.json
Fetch 'collector-health.yaml' "$root\no-defaults\collector-health.yaml"
@'
{"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[{"id":"wec-security","channel":"ForwardedEvents","eventIds":[4625],"providers":["Microsoft-Windows-Security-Auditing"],"pack":"windows-security-logon","parser":0,"readExisting":true,"pollIntervalSeconds":1,"batchSize":256}]}
'@ | Set-Content "$root\windows-eventlog.json" -Encoding ASCII
@"
# Operator settings; upgrades and repairs keep this file (BOWER_SETTINGS_FILE).
BOWER_INGEST_TOKEN_FILE=$root\secrets\token
BOWER_POLICY_DIRECTORY=$root\no-defaults
BOWER_OUTPUT=azure-logs-ingestion
BOWER_AZURE_CREDENTIAL=environment
BOWER_STREAM_NAME=Custom-BowerSecurity
BOWER_DCE_ENDPOINT=$($s.dce)
BOWER_DCR_ID=$($s.dcr)
AZURE_TENANT_ID=$($s.tenant)
AZURE_CLIENT_ID=$($s.client)
AZURE_CLIENT_CERTIFICATE_PATH=$root\secrets\ingest.pem
BOWER_PACKS=$root\packs\windows.bowerpack
BOWER_PACK_TRUSTED_KEYS=$root\keys\pack-signing.pub.pem
BOWER_PRIVACY_HMAC_KEY_FILE=$root\secrets\hmac.key
BOWER_WINDOWS_EVENTLOG_CONFIG=$root\windows-eventlog.json
BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60
BOWER_DELIVERY_LEASE_SECONDS=90
BOWER_DELIVERY_TIMEOUT_SECONDS=60
BOWER_QUEUE_MAX_BYTES=4294967296
BOWER_QUEUE_RETENTION_HOURS=2
"@ | Set-Content "$root\bower.env" -Encoding ASCII
$sid = 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086'
$channel = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents')
if ($channel.SecurityDescriptor -notlike "*$sid*") { $channel.SecurityDescriptor += "(A;;0x1;;;$sid)"; $channel.SaveChanges() }
$channel.Dispose()
wevtutil.exe sl ForwardedEvents /ms:4294967296
if ($LASTEXITCODE -ne 0) { throw 'Unable to size ForwardedEvents' }
Start-Service Bower
$healthy = $false
for ($i = 0; $i -lt 60 -and -not $healthy; $i++) { try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; $healthy = $true } catch { Start-Sleep -Seconds 2 } }
if (-not $healthy) { throw 'collector-health-not-ready' }
$powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$check = "-NoProfile -ExecutionPolicy Bypass -File `"$root\monitoring\Test-BowerCollectorHealth.ps1`" -TokenFile `"$root\secrets\token`" -QueuePath `"$root\state\queue.db`" -QueueMaxBytes 4294967296 -WecSubscription Bower-Security-4625 -StateFile `"$root\monitoring\healthcheck-state.json`" -WriteEventLog"
Register-ScheduledTask -TaskName 'BowerCollectorHealth' -User SYSTEM -RunLevel Highest `
    -Action (New-ScheduledTaskAction -Execute $powershell -Argument $check) `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew) | Out-Null
$service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
[ordered]@{
    serviceAccount = $service.StartName; serviceState = $service.State; imagePath = $service.PathName
    product = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
    msiSha256 = (Get-FileHash C:\BowerLab\artifacts\collector.msi -Algorithm SHA256).Hash.ToLowerInvariant()
    collectorSha256 = (Get-FileHash 'C:\Program Files\Bower\Bower.Collector.exe' -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    msiSignature = (Get-AuthenticodeSignature C:\BowerLab\artifacts\collector.msi).Status.ToString()
    settingsSha256 = (Get-FileHash "$root\bower.env" -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json
