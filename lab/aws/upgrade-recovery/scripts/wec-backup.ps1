$ErrorActionPreference = 'Stop'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
if (!(Test-Path C:\BowerLab\prcli\bower.exe)) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/pr-cli-win-x64.zip' C:\BowerLab\pr-cli.zip --region '{{REGION}}' --only-show-errors
    Expand-Archive C:\BowerLab\pr-cli.zip -DestinationPath C:\BowerLab\prcli -Force
}
$dir = 'C:\BowerLab\backup'
New-Item -ItemType Directory -Force $dir | Out-Null
icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
$out = "$dir\{{NAME}}.bowerbackup"
$start = [DateTimeOffset]::UtcNow
$json = & C:\BowerLab\prcli\bower.exe queue backup --database C:\ProgramData\Bower\state\queue.db --output $out --collector-id {{COLLECTOR_ID}}
if ($LASTEXITCODE -ne 0) { throw "backup failed $LASTEXITCODE" }
$end = [DateTimeOffset]::UtcNow
& $aws s3 cp $out "s3://{{Artifacts}}/backups/{{NAME}}.bowerbackup" --region '{{REGION}}' --only-show-errors
& $aws s3 cp "$out.manifest.json" "s3://{{Artifacts}}/backups/{{NAME}}.bowerbackup.manifest.json" --region '{{REGION}}' --only-show-errors
& $aws s3 cp "$out.manifest.json" "s3://{{Artifacts}}/results/$env:COMPUTERNAME/{{NAME}}.manifest.json" --region '{{REGION}}' --only-show-errors
$m = ($json -join "`n") | ConvertFrom-Json
[ordered]@{ name='{{NAME}}'; startedAt=$start.ToString('o'); seconds=[Math]::Round(($end-$start).TotalSeconds,2); bytes=$m.databaseBytes; counts=$m.counts; cursors=$m.sourceCursors; ledger="$($m.ledgerSequence)"; intact=$m.ledgerIntact; integrity=$m.integrityCheck; collector=$m.collectorId; cliSha256=(Get-FileHash C:\BowerLab\prcli\bower.exe -Algorithm SHA256).Hash.ToLowerInvariant() } | ConvertTo-Json -Compress
