$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Runs the per-poll profiler (lab/aws/wecfix/bench) against ForwardedEvents. Metadata only.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$bench = 'C:\BowerLab\bench\{{BENCH}}.exe'
New-Item -ItemType Directory -Force C:\BowerLab\bench | Out-Null
if (!(Test-Path $bench)) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/bench/{{BENCH}}.exe' $bench --region '{{REGION}}' --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'bench download failed' }
}
$service = (Get-CimInstance Win32_Service -Filter "Name='EventLog'").ProcessId
$sha = (Get-FileHash $bench -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "bench=$sha eventlogPid=$service host=$env:COMPUTERNAME"
& $bench {{MODE}} --channel ForwardedEvents --event-ids 4625 --providers Microsoft-Windows-Security-Auditing --polls {{POLLS}} --service-pid $service {{EXTRA}}
if ($LASTEXITCODE -ne 0) { throw "bench exit $LASTEXITCODE" }
