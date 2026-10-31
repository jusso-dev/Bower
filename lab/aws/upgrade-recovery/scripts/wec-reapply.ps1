$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\Bower'
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
Restart-Service Bower
Start-Sleep -Seconds 8
$s=Get-CimInstance Win32_Service -Filter "Name='Bower'"
[ordered]@{ at=[DateTimeOffset]::UtcNow.ToString('o'); state=$s.State; envNames=@((Get-ItemProperty $key).Environment).Count } | ConvertTo-Json -Compress
