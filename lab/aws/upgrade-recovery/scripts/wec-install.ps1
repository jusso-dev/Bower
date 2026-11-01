$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
function Fetch($name, $path) {
    & $aws s3 cp "s3://{{Artifacts}}/$name" $path --region '{{REGION}}' --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "download failed: $name" }
}
New-Item -ItemType Directory -Force C:\BowerLab\artifacts | Out-Null
foreach ($f in 'old.msi','new.msi','windows-security-logon-1.0.2.bowerpack','bower-signing.pub.pem','cli-win-x64.zip','legacy-74e250f-win-x64.zip') { Fetch "artifacts/$f" "C:\BowerLab\artifacts\$f" }
Expand-Archive C:\BowerLab\artifacts\cli-win-x64.zip -DestinationPath C:\BowerLab\cli -Force
$install = Start-Process msiexec.exe -ArgumentList '/i C:\BowerLab\artifacts\old.msi /qn /norestart COLLECTORID={{COLLECTOR_ID}} BOWERENVIRONMENT=validation /l*v C:\BowerLab\install-old.log' -Wait -PassThru
if ($install.ExitCode -notin @(0,3010)) { throw "MSI failed: $($install.ExitCode)" }
Stop-Service Bower
$root = 'C:\ProgramData\Bower'
Copy-Item C:\BowerLab\artifacts\windows-security-logon-1.0.2.bowerpack "$root\packs\windows.bowerpack"
Copy-Item C:\BowerLab\artifacts\bower-signing.pub.pem "$root\keys\bower-signing.pub.pem"
Fetch 'credentials/ingest.pem' "$root\secrets\ingest.pem"
Fetch 'credentials/hmac-wec' "$root\secrets\hmac.key"
Fetch 'credentials/token-wec' "$root\secrets\token"
New-Item -ItemType Directory -Force "$root\no-defaults" | Out-Null
@'
{"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[{"id":"wec-security","channel":"ForwardedEvents","eventIds":[4625],"providers":["Microsoft-Windows-Security-Auditing"],"pack":"windows-security-logon","parser":0,"readExisting":true,"pollIntervalSeconds":1,"batchSize":256}]}
'@ | Set-Content "$root\windows-eventlog.json" -Encoding ASCII
$sid = 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086'
$channel = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents')
if ($channel.SecurityDescriptor -notlike "*$sid*") { $channel.SecurityDescriptor += "(A;;0x1;;;$sid)"; $channel.SaveChanges() }
$channel.Dispose()
# dev.264 has no settings file: the documented way was editing the service Environment value.
$settings = [ordered]@{
 BOWER_INGEST_TOKEN_FILE="$root\secrets\token"; BOWER_POLICY_DIRECTORY="$root\no-defaults";
 BOWER_OUTPUT='azure-logs-ingestion'; BOWER_AZURE_CREDENTIAL='environment';
 BOWER_DCE_ENDPOINT='{{DCE}}'; BOWER_DCR_ID='{{DCR}}';
 AZURE_TENANT_ID='{{AZURE_TENANT}}'; AZURE_CLIENT_ID='{{AZURE_CLIENT}}';
 AZURE_CLIENT_CERTIFICATE_PATH="$root\secrets\ingest.pem";
 BOWER_PACKS="$root\packs\windows.bowerpack"; BOWER_PACK_TRUSTED_KEYS="$root\keys\bower-signing.pub.pem";
 BOWER_PRIVACY_HMAC_KEY_FILE="$root\secrets\hmac.key"; BOWER_WINDOWS_EVENTLOG_CONFIG="$root\windows-eventlog.json";
 BOWER_DELIVERY_LEASE_SECONDS='90'; BOWER_DELIVERY_TIMEOUT_SECONDS='60'
}
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
$envs = @((Get-ItemProperty $key).Environment | Where-Object { !$settings.Contains(($_ -split '=',2)[0]) })
$envs += @($settings.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value })
Set-ItemProperty $key Environment -Value $envs -Type MultiString
$service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
[ordered]@{serviceAccount=$service.StartName;serviceState=$service.State;imagePath=$service.PathName;product=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion;queueExists=(Test-Path "$root\state\queue.db")} | ConvertTo-Json
