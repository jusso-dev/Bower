# Installs the drill's Windows collector as the Bower service (NT SERVICE\Bower), a
# collector-initiated WEC subscription forwarding local Security 4625 into ForwardedEvents,
# a failed-logon generator and the health-check scheduled task. Prints no secret values.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not $env:BOWER_LAB_BUCKET) { throw 'BOWER_LAB_BUCKET is required' }

$stage = Join-Path $env:TEMP 'bower-stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -KeyPrefix 'artifacts/windows' -Folder $stage -Region $env:AWS_DEFAULT_REGION | Out-Null

$install = 'C:\Program Files\Bower'
$data = 'C:\ProgramData\Bower'
if (Get-Service Bower -ErrorAction SilentlyContinue) { Stop-Service Bower -Force -ErrorAction SilentlyContinue }
if (Test-Path $install) { Remove-Item $install -Recurse -Force }
Expand-Archive -Path (Join-Path $stage 'collector.zip') -DestinationPath $stage -Force
Move-Item -Path (Join-Path $stage 'collector-win-x64') -Destination $install
# A move keeps the restrictive TEMP ACL; inherit Program Files permissions instead.
& icacls.exe $install /reset /T /Q | Out-Null
foreach ($folder in 'data', 'secrets', 'packs', 'keys', 'monitoring') {
    New-Item -ItemType Directory -Path (Join-Path $data $folder) -Force | Out-Null
}
if (Test-Path (Join-Path $data 'policies')) { Remove-Item (Join-Path $data 'policies') -Recurse -Force }
Expand-Archive -Path (Join-Path $stage 'policies.zip') -DestinationPath $data -Force
Copy-Item (Join-Path $stage 'ingest-token') (Join-Path $data 'secrets\ingest-token') -Force
Copy-Item (Join-Path $stage 'ingest.pem') (Join-Path $data 'secrets\ingest.pem') -Force
Copy-Item (Join-Path $stage 'hmac.key') (Join-Path $data 'secrets\hmac.key') -Force
Copy-Item (Join-Path $stage 'windows-security-logon-1.0.2.bowerpack') (Join-Path $data 'packs\') -Force
Copy-Item (Join-Path $stage 'pack-signing.pub.pem') (Join-Path $data 'keys\pack-signing.pub.pem') -Force
Copy-Item (Join-Path $stage 'windows-eventlog.json') (Join-Path $data 'windows-eventlog.json') -Force
Copy-Item (Join-Path $stage 'source-expectations.json') (Join-Path $data 'source-expectations.json') -Force
Copy-Item (Join-Path $stage 'Test-BowerCollectorHealth.ps1') (Join-Path $data 'monitoring\Test-BowerCollectorHealth.ps1') -Force

$settings = Get-Content (Join-Path $stage 'settings.json') -Raw | ConvertFrom-Json
Remove-Item $stage -Recurse -Force

if (-not (Get-Service Bower -ErrorAction SilentlyContinue)) {
    & sc.exe create Bower binPath= "`"$install\Bower.Collector.exe`"" start= auto obj= 'NT SERVICE\Bower' DisplayName= 'Bower Security Telemetry Collector' | Out-Null
}
# Windows PowerShell 5.1 strips the embedded quotes from the sc.exe argument; an unquoted path
# with a space fails with "file not found". Set the quoted image path directly.
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower' -Name ImagePath -Type ExpandString -Value "`"$install\Bower.Collector.exe`""
# Same recovery as the MSI: restart after each failure, reset daily.
& sc.exe failure Bower reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
& sc.exe failureflag Bower 1 | Out-Null
$environment = @(
    'BOWER_LISTEN_URL=http://127.0.0.1:4319',
    "BOWER_QUEUE_PATH=$data\data\bower.db",
    "BOWER_POLICY_DIRECTORY=$data\policies",
    'BOWER_COLLECTOR_ID=ws6-windows-01',
    'BOWER_ENVIRONMENT=lab',
    "BOWER_INGEST_TOKEN_FILE=$data\secrets\ingest-token",
    'BOWER_OUTPUT=azure-logs-ingestion',
    "BOWER_DCE_ENDPOINT=$($settings.dce)",
    "BOWER_DCR_ID=$($settings.dcr)",
    'BOWER_AZURE_CREDENTIAL=environment',
    "AZURE_TENANT_ID=$($settings.tenant)",
    "AZURE_CLIENT_ID=$($settings.client)",
    "AZURE_CLIENT_CERTIFICATE_PATH=$data\secrets\ingest.pem",
    "BOWER_PACKS=$data\packs\windows-security-logon-1.0.2.bowerpack",
    "BOWER_PACK_TRUSTED_KEYS=$data\keys\pack-signing.pub.pem",
    "BOWER_PRIVACY_HMAC_KEY_FILE=$data\secrets\hmac.key",
    "BOWER_WINDOWS_EVENTLOG_CONFIG=$data\windows-eventlog.json",
    "BOWER_SOURCE_EXPECTATIONS=$data\source-expectations.json",
    'BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60',
    'BOWER_DELIVERY_LEASE_SECONDS=90',
    'BOWER_DELIVERY_TIMEOUT_SECONDS=60',
    'BOWER_QUEUE_MAX_BYTES=4194304'
)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower' -Name Environment -Type MultiString -Value $environment
if (-not [Diagnostics.EventLog]::SourceExists('Bower.Collector')) { New-EventLog -LogName Application -Source 'Bower.Collector' }

# The virtual account exists once the service does.
$sid = (New-Object Security.Principal.NTAccount('NT SERVICE\Bower')).Translate([Security.Principal.SecurityIdentifier]).Value
& icacls.exe "$data\data" /grant "*${sid}:(OI)(CI)M" | Out-Null
foreach ($path in "$data\policies", "$data\packs", "$data\keys", "$data\windows-eventlog.json", "$data\source-expectations.json") {
    & icacls.exe $path /grant "*${sid}:(OI)(CI)RX" | Out-Null
}
& icacls.exe "$data\secrets" /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "*${sid}:(OI)(CI)R" | Out-Null

# WEC: collector-initiated subscription to this host's Security 4625 events.
& winrm.cmd quickconfig -quiet | Out-Null
& wecutil.exe qc /q | Out-Null
$readers = (& net.exe localgroup 'Event Log Readers') -join "`n"
if ($readers -notmatch 'NETWORK SERVICE') { & net.exe localgroup 'Event Log Readers' 'NT AUTHORITY\NETWORK SERVICE' /add | Out-Null }
# Group membership reaches the WEC and WinRM tokens only after a restart (else WSMan access denied).
Restart-Service WinRM -Force
Restart-Service Wecsvc -Force
& wevtutil.exe sl ForwardedEvents /ms:1073741824
$sddl = (& wevtutil.exe gl ForwardedEvents | Select-String '^channelAccess:\s*(.+)$').Matches[0].Groups[1].Value.Trim()
if ($sddl -notmatch [regex]::Escape($sid)) { & wevtutil.exe sl ForwardedEvents "/ca:$sddl(A;;0x1;;;$sid)" }
$subscription = @'
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>bower-forwarded</SubscriptionId>
  <SubscriptionType>CollectorInitiated</SubscriptionType>
  <Description>Bower monitoring drill: local Security 4625 to ForwardedEvents</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Pull">
    <Batching><MaxItems>20</MaxItems><MaxLatencyTime>5000</MaxLatencyTime></Batching>
    <PushSettings><Heartbeat Interval="60000"/></PushSettings>
  </Delivery>
  <Query><![CDATA[<QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4625)]]</Select></Query></QueryList>]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <CredentialsType>Default</CredentialsType>
  <EventSources><EventSource Enabled="true"><Address>localhost</Address></EventSource></EventSources>
</Subscription>
'@
$subscriptionFile = Join-Path $env:TEMP 'bower-forwarded.xml'
Set-Content -Path $subscriptionFile -Value $subscription -Encoding UTF8
if ((& wecutil.exe es) -contains 'bower-forwarded') { & wecutil.exe ds bower-forwarded }
& wecutil.exe cs $subscriptionFile
Remove-Item $subscriptionFile
& auditpol.exe /set /subcategory:'Logon' /failure:enable | Out-Null

# Generator: one failed network logon of a nonexistent account every five seconds.
$generator = @'
while ($true) {
    & net.exe use \\127.0.0.1\IPC$ /user:bower-probe 'Wrong-Pass-1' 2>$null | Out-Null
    Start-Sleep -Seconds 5
}
'@
Set-Content -Path "$data\monitoring\generator.ps1" -Value $generator -Encoding UTF8
$powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
Unregister-ScheduledTask -TaskName 'BowerDrillGenerator' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'BowerDrillGenerator' -User 'SYSTEM' -RunLevel Highest -Force `
    -Action (New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$data\monitoring\generator.ps1`"") `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew) | Out-Null

# Health check every minute, verdict written to the Application log (Bower.HealthCheck).
$check = "-NoProfile -ExecutionPolicy Bypass -File `"$data\monitoring\Test-BowerCollectorHealth.ps1`" -TokenFile `"$data\secrets\ingest-token`" -QueuePath `"$data\data\bower.db`" -QueueMaxBytes 4194304 -WecSubscription bower-forwarded -StateFile `"$data\monitoring\healthcheck-state.json`" -WriteEventLog"
Unregister-ScheduledTask -TaskName 'BowerHealthCheck' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'BowerHealthCheck' -User 'SYSTEM' -RunLevel Highest -Force `
    -Action (New-ScheduledTaskAction -Execute $powershell -Argument $check) `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew) | Out-Null

Start-Service Bower
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try { Invoke-RestMethod -Uri 'http://127.0.0.1:4319/health' -TimeoutSec 3 | Out-Null; break } catch { Start-Sleep -Seconds 2 }
}
Start-ScheduledTask -TaskName 'BowerDrillGenerator'
Start-Sleep -Seconds 45
"service: $((Get-Service Bower).Status)"
& wecutil.exe gr bower-forwarded | Select-String 'RunTimeStatus|LastError|ErrorMessage' | ForEach-Object { $_.Line.Trim() }
(Get-FileHash "$install\Bower.Collector.exe").Hash
(Get-FileHash "$install\Bower.Collector.dll").Hash
(Get-FileHash "$data\packs\windows-security-logon-1.0.2.bowerpack").Hash
$token = (Get-Content "$data\secrets\ingest-token" -Raw).Trim()
$status = Invoke-RestMethod -Uri 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" }
[ordered]@{ status = $status.status; queue = $status.queue; windowsEventLog = $status.windowsEventLog; sources = $status.sources } | ConvertTo-Json -Depth 4 -Compress
