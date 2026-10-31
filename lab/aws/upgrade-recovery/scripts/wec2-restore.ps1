$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
function Fetch($name, $path) { & $aws s3 cp "s3://{{Artifacts}}/$name" $path --region '{{REGION}}' --only-show-errors; if ($LASTEXITCODE -ne 0) { throw "download $name" } }
New-Item -ItemType Directory -Force C:\BowerLab\artifacts, C:\BowerLab\restore | Out-Null
icacls C:\BowerLab\restore /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
foreach ($f in 'pr.msi','pr-cli-win-x64.zip','windows-security-logon-1.0.2.bowerpack','bower-signing.pub.pem','old.msi') { Fetch "artifacts/$f" "C:\BowerLab\artifacts\$f" }
Expand-Archive C:\BowerLab\artifacts\pr-cli-win-x64.zip -DestinationPath C:\BowerLab\prcli -Force
Fetch 'backups/{{NAME}}.bowerbackup' 'C:\BowerLab\restore\{{NAME}}.bowerbackup'
Fetch 'backups/{{NAME}}.bowerbackup.manifest.json' 'C:\BowerLab\restore\{{NAME}}.bowerbackup.manifest.json'
$p = Start-Process msiexec.exe -ArgumentList '/i C:\BowerLab\artifacts\pr.msi /qn /norestart COLLECTORID=wec-ws4 BOWERENVIRONMENT=validation /l*v C:\BowerLab\install-pr.log' -Wait -PassThru
if ($p.ExitCode -notin 0,3010) { throw "MSI $($p.ExitCode)" }
Stop-Service Bower
$root = 'C:\ProgramData\Bower'
# The MSI's first start created an empty queue; restore never overwrites, so move it aside.
New-Item -ItemType Directory -Force C:\BowerLab\fresh-queue | Out-Null
Get-ChildItem "$root\state" -Filter 'queue.db*' | Move-Item -Destination C:\BowerLab\fresh-queue
$restoreStart = [DateTimeOffset]::UtcNow
$json = & C:\BowerLab\prcli\bower.exe queue restore --backup 'C:\BowerLab\restore\{{NAME}}.bowerbackup' --database "$root\state\queue.db" 2>$null
if ($LASTEXITCODE -ne 0) { throw "restore failed $LASTEXITCODE" }
$restoreSeconds = [Math]::Round(([DateTimeOffset]::UtcNow - $restoreStart).TotalSeconds, 2)
Copy-Item C:\BowerLab\artifacts\windows-security-logon-1.0.2.bowerpack "$root\packs\windows.bowerpack"
Copy-Item C:\BowerLab\artifacts\bower-signing.pub.pem "$root\keys\bower-signing.pub.pem"
Fetch 'credentials/ingest.pem' "$root\secrets\ingest.pem"
Fetch 'credentials/hmac-wec' "$root\secrets\hmac.key"
Fetch 'credentials/token-wec' "$root\secrets\token"
New-Item -ItemType Directory -Force "$root\no-defaults" | Out-Null
'{"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[{"id":"wec-security","channel":"ForwardedEvents","eventIds":[4625],"providers":["Microsoft-Windows-Security-Auditing"],"pack":"windows-security-logon","parser":0,"readExisting":true,"pollIntervalSeconds":1,"batchSize":256}]}' | Set-Content "$root\windows-eventlog.json" -Encoding ASCII
@"
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
$sid = 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086'
$channel = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents')
if ($channel.SecurityDescriptor -notlike "*$sid*") { $channel.SecurityDescriptor += "(A;;0x1;;;$sid)"; $channel.SaveChanges() }
$channel.Dispose()
$dbAcl = Get-Acl "$root\state\queue.db"
Start-Service Bower
Start-Sleep -Seconds 10
$m = ($json -join "`n") | ConvertFrom-Json
[ordered]@{ restoredAt=$restoreStart.ToString('o'); restoreSeconds=$restoreSeconds; counts=$m.Counts; cursors=$m.SourceCursors; ledger=$m.LedgerSequence; integrity=$m.IntegrityCheck
  queueAclRules=@($dbAcl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }); service=(Get-Service Bower).Status.ToString(); forwardedRecords=(Get-WinEvent -ListLog ForwardedEvents).RecordCount } | ConvertTo-Json -Depth 4 -Compress
