$ErrorActionPreference = 'Stop'
# Replace the DC's probe with a reviewed revision (SHA-256 pinned) between exporter runs.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$new = 'C:\BowerLab\soak\probe-next.exe'
& $aws s3 cp 's3://{{Artifacts}}/artifacts/soak/dc/{{PROBE_NAME}}' $new --region '{{REGION}}' --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'download failed' }
if ((Get-FileHash $new -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{PROBE_SHA256}}') { throw 'probe digest mismatch' }
Move-Item $new C:\BowerLab\soak\probe.exe -Force
"probe updated {{PROBE_SHA256}}"
