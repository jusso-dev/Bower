# Storage-pressure lab: WEC + Bower collector on a dedicated 2 GiB queue volume (Q:).
# Run through storage-lab.py after the domain join. Prints metadata only.
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
foreach ($name in 'BOWER_DCE','BOWER_DCR','BOWER_TENANT','BOWER_PUBLISHER') {
    if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is required" }
}
Import-Module AWSPowerShell
$work = 'C:\ws3'; $artifacts = "$work\artifacts"
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$prefix = "$env:BOWER_LAB_RUN/artifacts/windows"
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key "$prefix/SHA256SUMS" -File "$artifacts\SHA256SUMS" | Out-Null
foreach ($line in Get-Content "$artifacts\SHA256SUMS") {
    $hash, $file = $line -split '\s+\*?', 2
    if ($file -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unexpected artifact name' }
    Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key "$prefix/$file" -File (Join-Path $artifacts $file) | Out-Null
    if ((Get-FileHash (Join-Path $artifacts $file) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw "Checksum mismatch: $file" }
}

# The queue volume: the only raw 2 GiB disk.
if (-not (Test-Path 'Q:\')) {
    $disk = @(Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -eq 2GB })
    if ($disk.Count -ne 1) { throw 'Expected exactly one raw 2 GiB disk' }
    Initialize-Disk -Number $disk[0].Number -PartitionStyle GPT
    New-Partition -DiskNumber $disk[0].Number -UseMaximumSize -DriveLetter Q | Out-Null
    Format-Volume -DriveLetter Q -FileSystem NTFS -NewFileSystemLabel bowerqueue -Confirm:$false | Out-Null
}

# Install or upgrade in place. The MSI rewrites the service Environment, so it is set again below.
$process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "$artifacts\collector.msi", '/qn', '/norestart',
    '/l*v', "$work\msi.log", 'COLLECTORID=ws3-wec', 'BOWERENVIRONMENT=validation')
if ($process.ExitCode -notin 0, 1638) { throw "MSI failed with $($process.ExitCode)" }
Stop-Service Bower -ErrorAction SilentlyContinue
$data = 'C:\ProgramData\Bower'
Copy-Item "$artifacts\windows-security-logon-1.0.2.bowerpack" "$data\packs\" -Force
Copy-Item "$artifacts\lab.pub.pem" "$data\keys\pack-trusted.pem" -Force
$secrets = "$data\secrets"
(Get-SECSecretValue -SecretId "bower-lab/$env:BOWER_LAB_RUN/publisher").SecretString | Set-Content -NoNewline -Encoding ascii "$secrets\azure-publisher.pem"
if (-not (Test-Path "$secrets\hmac.key")) {
    $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [Convert]::ToBase64String($bytes) | Set-Content -NoNewline -Encoding ascii "$secrets\hmac.key"
    $bytes = New-Object byte[] 36; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ([Convert]::ToBase64String($bytes) -replace '[+/=]','') | Set-Content -NoNewline -Encoding ascii "$secrets\ingest-token"
}
# After storage-wec-layout.ps1 the volume is mounted at the state folder (default path).
$mounted = (Get-Partition -DriveLetter Q).AccessPaths -contains 'C:\ProgramData\Bower\state\'
$queuePath = if ($mounted) { 'C:\ProgramData\Bower\state\queue.db' } else { 'Q:\bower\queue.db' }
if (-not $mounted) {
    New-Item -ItemType Directory -Force -Path 'Q:\bower' | Out-Null
    icacls 'Q:\bower' /inheritance:r /grant:r 'NT SERVICE\Bower:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' | Out-Null
}
foreach ($file in "$secrets\azure-publisher.pem", "$secrets\hmac.key", "$secrets\ingest-token") { icacls $file /grant 'NT SERVICE\Bower:R' | Out-Null }
@'
{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
  {"id": "forwarded-security", "channel": "ForwardedEvents", "eventIds": [4625],
   "providers": ["Microsoft-Windows-Security-Auditing"], "pack": "windows-security-logon", "parser": 0,
   "readExisting": true, "batchSize": 256, "pollIntervalSeconds": 1}]}
'@ | Set-Content -Encoding ascii "$data\windows-eventlog.json"

# WEC: source-initiated Security 4625 from domain controllers into ForwardedEvents.
winrm quickconfig -quiet | Out-Null
wecutil qc /q | Out-Null
Set-Service Wecsvc -StartupType Automatic
$maxBytes = if ($env:BOWER_FORWARDED_BYTES) { [long]$env:BOWER_FORWARDED_BYTES } else { 67108864 }
wevtutil sl ForwardedEvents /ms:$maxBytes /rt:false
$sid = ((sc.exe showsid Bower) | Select-String 'SERVICE SID:').ToString().Split(':',2)[1].Trim()
$access = (wevtutil gl ForwardedEvents | Select-String '^channelAccess:').ToString().Split(' ',2)[1].Trim()
if ($access -notmatch [regex]::Escape($sid)) { wevtutil sl ForwardedEvents "/ca:$access(A;;0x1;;;$sid)" }
@'
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>ws3-security</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Storage-pressure lab: Security 4625 from domain controllers</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching><MaxItems>256</MaxItems><MaxLatencyTime>1000</MaxLatencyTime></Batching>
    <PushSettings><Heartbeat Interval="60000"/></PushSettings>
  </Delivery>
  <Query><![CDATA[<QueryList><Query Id="0"><Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4625)]]</Select></Query></QueryList>]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>Events</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)(A;;GA;;;DD)S:</AllowedSourceDomainComputers>
</Subscription>
'@ | Set-Content -Encoding ascii "$work\subscription.xml"
if ((wecutil es) -notcontains 'ws3-security') { wecutil cs "$work\subscription.xml" }

$environment = @(
    'BOWER_LISTEN_URL=http://127.0.0.1:4319', "BOWER_QUEUE_PATH=$queuePath",
    "BOWER_POLICY_DIRECTORY=$data\policies", 'BOWER_COLLECTOR_ID=ws3-wec', 'BOWER_ENVIRONMENT=validation',
    "BOWER_PACKS=$data\packs\windows-security-logon-1.0.2.bowerpack", "BOWER_PACK_TRUSTED_KEYS=$data\keys\pack-trusted.pem",
    "BOWER_PRIVACY_HMAC_KEY_FILE=$secrets\hmac.key", "BOWER_INGEST_TOKEN_FILE=$secrets\ingest-token",
    "BOWER_WINDOWS_EVENTLOG_CONFIG=$data\windows-eventlog.json",
    'BOWER_OUTPUT=azure-logs-ingestion', "BOWER_DCE_ENDPOINT=$env:BOWER_DCE", "BOWER_DCR_ID=$env:BOWER_DCR",
    'BOWER_AZURE_CREDENTIAL=environment', "AZURE_TENANT_ID=$env:BOWER_TENANT", "AZURE_CLIENT_ID=$env:BOWER_PUBLISHER",
    "AZURE_CLIENT_CERTIFICATE_PATH=$secrets\azure-publisher.pem",
    'BOWER_DELIVERY_LEASE_SECONDS=90', 'BOWER_DELIVERY_TIMEOUT_SECONDS=60',
    "BOWER_QUEUE_MAX_BYTES=$(if ($env:BOWER_QUEUE_MAX_BYTES) { $env:BOWER_QUEUE_MAX_BYTES } else { '268435456' })",
    'BOWER_STORAGE_WARNING_FREE_BYTES=536870912', 'BOWER_STORAGE_WARNING_FREE_PERCENT=0',
    'BOWER_STORAGE_CRITICAL_FREE_BYTES=268435456', 'BOWER_STORAGE_CRITICAL_FREE_PERCENT=0',
    'BOWER_QUEUE_PRESSURE_RETENTION_MINUTES=5')
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower' -Name Environment -Type MultiString -Value $environment
sc.exe config Bower start= auto | Out-Null
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower' -Name DelayedAutostart -ErrorAction SilentlyContinue
Start-Service Bower
$token = Get-Content "$secrets\ingest-token" -Raw
$status = $null
foreach ($attempt in 1..60) {
    try { $status = Invoke-RestMethod -Uri 'http://127.0.0.1:4319/v1/status' -Headers @{Authorization = "Bearer $token"}; break } catch { Start-Sleep 2 }
}
$forwarded = Get-WinEvent -ListLog ForwardedEvents
[ordered]@{
    phase = 'wec-setup'; msiSha256 = (Get-FileHash "$artifacts\collector.msi" -Algorithm SHA256).Hash.ToLowerInvariant()
    version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
    queueVolume = (Get-Volume -DriveLetter Q | Select-Object FileSystem, Size, SizeRemaining)
    forwardedEventsMaximumBytes = $forwarded.MaximumSizeInBytes; subscriptions = @(wecutil es)
    health = $status.status; storage = $status.storage
    windowsEventLog = @($status.windowsEventLog | Select-Object id, channel, state)
} | ConvertTo-Json -Depth 5 -Compress
