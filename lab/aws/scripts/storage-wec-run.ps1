# Runs one storage-pressure scenario on the WEC/collector host through storage-lab.py.
# The driver comes from this run's checksummed artifacts; results are metadata only.
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
if ($env:BOWER_SCENARIO -notmatch '^(smoke|queue-cap|watermarks|disk-full|reconcile|probe)$') { throw 'Unexpected scenario' }
Import-Module AWSPowerShell
$artifacts = 'C:\ws3\artifacts'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$prefix = "$env:BOWER_LAB_RUN/artifacts/windows"
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key "$prefix/SHA256SUMS" -File "$artifacts\SHA256SUMS" | Out-Null
foreach ($line in Get-Content "$artifacts\SHA256SUMS") {
    $hash, $file = $line -split '\s+\*?', 2
    if ($file -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unexpected artifact name' }
    Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key "$prefix/$file" -File (Join-Path $artifacts $file) | Out-Null
    if ((Get-FileHash (Join-Path $artifacts $file) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw "Checksum mismatch: $file" }
}
$env:PATH = "C:\ws3;$env:PATH"
$arguments = @{ Scenario = $env:BOWER_SCENARIO }
if ($env:BOWER_RATE) { $arguments.Rate = [int]$env:BOWER_RATE }
if ($env:BOWER_HOLD) { $arguments.Hold = [int]$env:BOWER_HOLD }
if ($env:BOWER_LIMIT) { $arguments.Limit = [int]$env:BOWER_LIMIT }
$output = & "$artifacts\storage-wec-driver.ps1" @arguments
$output | Set-Content -Encoding utf8 "C:\ws3\logs\$env:BOWER_SCENARIO-stdout.json"
foreach ($file in Get-ChildItem "C:\ws3\logs\$env:BOWER_SCENARIO*") {
    Write-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key "$env:BOWER_LAB_RUN/results/windows/$($file.Name)" -File $file.FullName | Out-Null
}
$output
