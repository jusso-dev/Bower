$ErrorActionPreference = 'Stop'
# Native 4625 identities for [FROM, TO) (epochs) from the DC Security log with Bower.LabProbe
# (lab/aws/upgrade-recovery/probe from #170), uploaded as results/wecfix/<run>/dc/NAME.*.
# Synthetic identities and counts only.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$dir = 'C:\BowerLab\wecfix\native'
New-Item -ItemType Directory -Force $dir | Out-Null
$probe = 'C:\BowerLab\wecfix\probe.exe'
if (!(Test-Path $probe)) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/wecfix/Bower.LabProbe.exe' $probe --region '{{REGION}}' --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'probe download failed' }
}
if ((Get-FileHash $probe -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{PROBE_SHA256}}') { throw 'probe digest mismatch' }
$out = "$dir\{{NAME}}.json"
if (Test-Path $out) { throw 'name already used' }
$from = [DateTimeOffset]::FromUnixTimeSeconds({{FROM}}).ToString('o'); $to = [DateTimeOffset]::FromUnixTimeSeconds({{TO}}).ToString('o')
& $probe native Security $from $out $to
if ($LASTEXITCODE -ne 0) { throw "probe exit $LASTEXITCODE" }
foreach ($f in $out, "$out.ids") {
    & $aws s3 cp $f "s3://{{Artifacts}}/results/wecfix/{{RUN_ID}}/dc/$(Split-Path $f -Leaf)" --region '{{REGION}}' --sse AES256 --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'upload failed' }
}
Get-Content $out
