$ErrorActionPreference = 'Stop'
# Pre-upgrade step: move operator settings from the service Environment value into bower.env.
$root = 'C:\ProgramData\Bower'
@"
# Operator settings; upgrades and repairs keep this file (BOWER_SETTINGS_FILE).
BOWER_INGEST_TOKEN_FILE=$root\secrets\token
BOWER_POLICY_DIRECTORY=$root\no-defaults
BOWER_OUTPUT=azure-logs-ingestion
BOWER_AZURE_CREDENTIAL=environment
BOWER_DCE_ENDPOINT={{DCE}}
BOWER_DCR_ID={{DCR}}
AZURE_TENANT_ID={{AZURE_TENANT}}
AZURE_CLIENT_ID={{AZURE_CLIENT}}
AZURE_CLIENT_CERTIFICATE_PATH=$root\secrets\ingest.pem
BOWER_PACKS=$root\packs\windows.bowerpack
BOWER_PACK_TRUSTED_KEYS=$root\keys\bower-signing.pub.pem
BOWER_PRIVACY_HMAC_KEY_FILE=$root\secrets\hmac.key
BOWER_WINDOWS_EVENTLOG_CONFIG=$root\windows-eventlog.json
BOWER_DELIVERY_LEASE_SECONDS=90
BOWER_DELIVERY_TIMEOUT_SECONDS=60
"@ | Set-Content "$root\bower.env" -Encoding ASCII
$acl = Get-Acl "$root\bower.env"
[ordered]@{ written = $true; sha256 = (Get-FileHash "$root\bower.env" -Algorithm SHA256).Hash.ToLowerInvariant(); owner = $acl.Owner; rules = @($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) } | ConvertTo-Json -Compress
