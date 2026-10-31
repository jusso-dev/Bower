# Refreshes the health-check script from the run's bucket.
$ErrorActionPreference = 'Stop'
Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key 'artifacts/windows/Test-BowerCollectorHealth.ps1' -File 'C:\ProgramData\Bower\monitoring\Test-BowerCollectorHealth.ps1' -Region $env:AWS_DEFAULT_REGION | Out-Null
(Get-FileHash 'C:\ProgramData\Bower\monitoring\Test-BowerCollectorHealth.ps1').Hash
