$ErrorActionPreference = 'Stop'
# One on-demand native 4625 identity export from the DC Security log for [FROM, TO) (epochs),
# uploaded as results/soak/<run>/dc/manual/NAME.*. Used for the smoke and interim checks before
# the scheduled hourly windows close; the scheduled export covers the same events again.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$dir = 'C:\BowerLab\soak\manual'
New-Item -ItemType Directory -Force $dir | Out-Null
$out = "$dir\{{NAME}}.json"
if (Test-Path $out) { throw 'name already used' }
$from = [DateTimeOffset]::FromUnixTimeSeconds({{FROM}}).ToString('o'); $to = [DateTimeOffset]::FromUnixTimeSeconds({{TO}}).ToString('o')
& C:\BowerLab\soak\probe.exe native Security $from $out $to
if ($LASTEXITCODE -ne 0) { throw "probe exit $LASTEXITCODE" }
foreach ($f in $out, "$out.ids") {
    & $aws s3 cp $f "s3://{{Artifacts}}/results/soak/{{RUN_ID}}/dc/manual/$(Split-Path $f -Leaf)" --region '{{REGION}}' --sse AES256 --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'upload failed' }
}
Get-Content $out
