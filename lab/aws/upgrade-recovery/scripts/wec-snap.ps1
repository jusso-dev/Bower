$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Metadata-only snapshot. Secrets are compared with an on-host baseline; only booleans leave the host.
$label = '{{LABEL}}'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$root = 'C:\ProgramData\Bower'
$snap = "C:\BowerLab\snap"
New-Item -ItemType Directory -Force $snap | Out-Null
if (!(Test-Path C:\BowerLab\probe\Bower.LabProbe.exe)) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/probe-win-x64.zip' C:\BowerLab\probe.zip --region '{{REGION}}' --only-show-errors
    Expand-Archive C:\BowerLab\probe.zip -DestinationPath C:\BowerLab\probe -Force
}
function Sha($path) { if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null } }
$service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
$exe = if ($service) { ($service.PathName -replace '^"([^"]+)".*$','$1') } else { $null }
$proc = if ($service -and $service.ProcessId) { Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue } else { $null }
$envValue = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower' -ErrorAction SilentlyContinue).Environment)
$secrets = @{}
foreach ($f in Get-ChildItem "$root\secrets" -File -ErrorAction SilentlyContinue) { $secrets[$f.Name] = Sha $f.FullName }
$baselinePath = 'C:\BowerLab\secret-baseline.json'
if (!(Test-Path $baselinePath)) { $secrets | ConvertTo-Json | Set-Content $baselinePath; icacls $baselinePath /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null }
$baseline = Get-Content $baselinePath -Raw | ConvertFrom-Json
$secretsUnchanged = $true
foreach ($p in $baseline.PSObject.Properties) { if ($secrets[$p.Name] -ne $p.Value) { $secretsUnchanged = $false } }
$acl = [ordered]@{}
foreach ($d in '', 'state', 'secrets', 'keys', 'packs', 'policies', 'enrolment', 'spool') {
    $path = Join-Path $root $d
    if (Test-Path $path) { $a = Get-Acl -LiteralPath $path; $acl[$(if ($d) { $d } else { 'root' })] = [ordered]@{ owner = $a.Owner; sddlSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($a.Sddl))).Replace('-','').ToLowerInvariant() } }
}
$status = $null
try {
    $token = [IO.File]::ReadAllText("$root\secrets\token").Trim()
    $status = Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 10
} catch { $status = $null }
$q = "$snap\$label-queue.json"
& C:\BowerLab\probe\Bower.LabProbe.exe queue "$root\state\queue.db" $q
if ($LASTEXITCODE -ne 0) { throw 'queue probe failed' }
$native = $null
if ('{{NATIVE_SINCE}}' -ne 'none') {
    $n = "$snap\$label-native.json"
    & C:\BowerLab\probe\Bower.LabProbe.exe native ForwardedEvents '{{NATIVE_SINCE}}' $n
    if ($LASTEXITCODE -ne 0) { throw 'native probe failed' }
    $native = Get-Content $n -Raw | ConvertFrom-Json
}
$fwd = Get-WinEvent -ListLog ForwardedEvents
$result = [ordered]@{
    label = $label; host = $env:COMPUTERNAME; capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    service = [ordered]@{ account = $service.StartName; state = $service.State; startMode = $service.StartMode; pathName = $service.PathName; processId = $service.ProcessId; processStart = $(if ($proc) { $proc.StartTime.ToUniversalTime().ToString('o') } else { $null }) }
    product = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
    executableSha256 = $(if ($exe) { Sha $exe } else { $null })
    environmentNames = @($envValue | ForEach-Object { ($_ -split '=',2)[0] })
    environmentSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(($envValue -join "`n")))).Replace('-','').ToLowerInvariant()
    settingsFileSha256 = Sha "$root\bower.env"
    windowsEventLogConfigSha256 = Sha "$root\windows-eventlog.json"
    packSha256 = Sha "$root\packs\windows.bowerpack"; trustedKeySha256 = Sha "$root\keys\bower-signing.pub.pem"
    secretsPresent = @($secrets.Keys | Sort-Object); secretsUnchanged = $secretsUnchanged
    acl = $acl
    forwardedEvents = [ordered]@{ records = $fwd.RecordCount; maximumBytes = $fwd.MaximumSizeInBytes }
    queue = Get-Content $q -Raw | ConvertFrom-Json
    native = $native
    status = $(if ($status) { [ordered]@{ status = $status.status; packs = $status.packs; policyHash = $status.policyHash; queue = $status.queue; delivery = $status.delivery; windowsEventLog = $status.windowsEventLog; ledgerHead = $status.ledgerHead } } else { $null })
}
$out = "$snap\$label.json"
$result | ConvertTo-Json -Depth 8 | Set-Content $out -Encoding UTF8
foreach ($f in Get-ChildItem $snap -Filter "$label*") {
    & $aws s3 cp $f.FullName "s3://{{Artifacts}}/results/$env:COMPUTERNAME/$($f.Name)" --region '{{REGION}}' --only-show-errors
}
[ordered]@{ label = $label; service = $result.service.state; account = $result.service.account; product = $result.product; queue = [ordered]@{ q = $result.queue.queued; up = $result.queue.uploading; re = $result.queue.retrying; del = $result.queue.delivered; dl = $result.queue.deadLettered; integrity = $result.queue.integrity }; cursors = $result.queue.cursors; wel = $(if ($status) { $status.windowsEventLog } else { 'status-unavailable' }); secretsUnchanged = $secretsUnchanged; envNames = $result.environmentNames.Count } | ConvertTo-Json -Depth 6 -Compress
