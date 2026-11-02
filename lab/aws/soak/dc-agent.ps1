$ErrorActionPreference = 'Stop'
# Soak agent on the domain controller (the native 4625 source). Rendered by lab.py.
#   ACTION=generator  register and start the generator task for LABEL (GEN_START, GEN_SECONDS, SMOKE)
#   ACTION=install    copy this agent and register the 15-minute native exporter: every closed
#                     window ([SMOKE_START, SOAK_START), then hourly from SOAK_START up to
#                     SOAK_SECONDS + 1 h) is exported once with Bower.LabProbe native identities
#                     and uploaded with the generator records. Metadata and synthetic ids only.
#   ACTION=status     print exported windows and generator progress
$Action = if ($args.Count -gt 0) { $args[0] } else { '{{ACTION}}' }
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$bucket = '{{Artifacts}}'; $region = '{{REGION}}'; $run = '{{RUN_ID}}'
$dir = 'C:\BowerLab\soak'
New-Item -ItemType Directory -Force $dir, "$dir\native" | Out-Null
function Fetch($name, $path) {
    & $aws s3 cp "s3://$bucket/artifacts/soak/dc/$name" $path --region $region --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "download failed: $name" }
}
function Put($path, $key) {
    & $aws s3 cp $path "s3://$bucket/results/soak/$run/dc/$key" --region $region --sse AES256 --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "upload failed: $key" }
}
function Assert-Hash($path, $expected) {
    if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw "digest mismatch: $path" }
}
if ($Action -eq 'generator') {
    Fetch 'generator-windows.ps1' "$dir\generator-windows.ps1"
    Assert-Hash "$dir\generator-windows.ps1" '{{GEN_SHA256}}'
    $name = 'BowerSoakGen-{{LABEL}}'
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'generator label already used' }
    $smoke = if ('{{SMOKE}}' -eq '1') { ' -Smoke' } else { '' }
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File $dir\generator-windows.ps1 -Target {{DcIp}} -StartEpoch {{GEN_START}} -Seconds {{GEN_SECONDS}} -Label {{LABEL}}$smoke"
    Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest `
        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 27) -AllowStartIfOnBatteries) | Out-Null
    Start-ScheduledTask -TaskName $name
    Write-Output "started $name start={{GEN_START}} seconds={{GEN_SECONDS}} smoke={{SMOKE}}"
    exit 0
}
$smokeStart = [long]'{{SMOKE_START}}'; $soakStart = [long]'{{SOAK_START}}'; $soakSeconds = [long]'{{SOAK_SECONDS}}'
$windows = @(,@('smoke', $smokeStart, $soakStart))
for ($k = 0; $k * 3600 -lt $soakSeconds + 3600; $k++) { $windows += ,@(('h{0:D2}' -f $k), ($soakStart + $k * 3600), ($soakStart + ($k + 1) * 3600)) }
if ($Action -eq 'install') {
    Copy-Item $PSCommandPath "$dir\agent.ps1" -Force
    Fetch 'Bower.LabProbe.exe' "$dir\probe.exe"
    Assert-Hash "$dir\probe.exe" '{{PROBE_SHA256}}'
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File $dir\agent.ps1 tick"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 2)
    Register-ScheduledTask -TaskName 'BowerSoakNative' -User SYSTEM -RunLevel Highest -Trigger $trigger `
        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 14) -MultipleInstances IgnoreNew) | Out-Null
    Write-Output "installed BowerSoakNative windows=$($windows.Count)"
    exit 0
}
if ($Action -eq 'tick') {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($w in $windows) {
        $out = "$dir\native\$($w[0]).json"
        if ((Test-Path $out) -or $now -lt $w[2] + 300) { continue }
        $from = [DateTimeOffset]::FromUnixTimeSeconds($w[1]).ToString('o'); $to = [DateTimeOffset]::FromUnixTimeSeconds($w[2]).ToString('o')
        & "$dir\probe.exe" native Security $from "$out.tmp" $to
        if ($LASTEXITCODE -ne 0) { Add-Content "$dir\errors.log" "$([DateTimeOffset]::UtcNow.ToString('o')) native $($w[0]) exit $LASTEXITCODE"; continue }
        Move-Item "$out.tmp.ids" "$out.ids" -Force; Move-Item "$out.tmp" $out -Force
        Put $out "native/$($w[0]).json"; Put "$out.ids" "native/$($w[0]).ids"
    }
    Get-ChildItem "$dir\gen" -Recurse -Filter *.json -ErrorAction SilentlyContinue | ForEach-Object { Put $_.FullName ("gen/" + $_.Directory.Name + "/" + $_.Name) }
    $security = Get-WinEvent -ListLog Security
    Add-Content "$dir\log-sizes.jsonl" (@{ at = [DateTimeOffset]::UtcNow.ToString('o'); securityRecords = $security.RecordCount; securityFileBytes = $security.FileSize; securityMaxBytes = $security.MaximumSizeInBytes; mode = $security.LogMode.ToString() } | ConvertTo-Json -Compress)
    Put "$dir\log-sizes.jsonl" 'log-sizes.jsonl'
    exit 0
}
if ($Action -eq 'status') {
    Get-ChildItem "$dir\native" -Filter *.json | ForEach-Object { $j = Get-Content $_.FullName -Raw | ConvertFrom-Json; "$($_.BaseName) selected=$($j.selected) distinct=$($j.distinct) dup=$($j.duplicateIdentities) changed=$($j.redactionChangedIds)" }
    Get-ChildItem "$dir\gen" -Recurse -Filter *.json -ErrorAction SilentlyContinue | Select-Object -Last 3 | ForEach-Object { "$($_.Directory.Name)/$($_.Name): " + (Get-Content $_.FullName -Raw) }
    Get-Content "$dir\errors.log" -ErrorAction SilentlyContinue | Select-Object -Last 5
    exit 0
}
throw "unknown action $Action"
