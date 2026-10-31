$ErrorActionPreference = 'Stop'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$o = 'C:\BowerLab\v1test\snap\dc-security-final.json'
& C:\BowerLab\v1test\probe\Bower.LabProbe.exe native Security '{{SINCE}}' $o
if ($LASTEXITCODE -ne 0) { throw 'probe failed' }
foreach ($f in $o, "$o.ids") { & $aws s3 cp $f "s3://{{Artifacts}}/results/BOWERDC/$(Split-Path $f -Leaf)" --region '{{REGION}}' --only-show-errors }
Get-Content $o
