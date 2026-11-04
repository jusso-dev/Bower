$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# CPU profile of the collector with the in-box Windows Performance Recorder (sampled stacks),
# reported by Bower.EtlStacks against the build's PDBs (SYMS=old|new). Prints sample counts per
# module and frame only; the trace is deleted afterwards.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$dir = 'C:\BowerLab\wecfix\profile'
New-Item -ItemType Directory -Force $dir, "$dir\syms-{{SYMS}}" | Out-Null
if (!(Test-Path "$dir\tool\Bower.EtlStacks.exe")) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/wecfix/etlstacks.zip' "$dir\etlstacks.zip" --region '{{REGION}}' --only-show-errors
    Expand-Archive "$dir\etlstacks.zip" "$dir\tool" -Force
}
if (!(Test-Path "$dir\syms-{{SYMS}}\Bower.Collector.pdb")) {
    & $aws s3 cp 's3://{{Artifacts}}/artifacts/wecfix/syms-{{SYMS}}.zip' "$dir\syms.zip" --region '{{REGION}}' --only-show-errors
    Expand-Archive "$dir\syms.zip" "$dir\syms-{{SYMS}}" -Force
}
Copy-Item 'C:\Program Files\Bower\Bower.Collector.exe', 'C:\Program Files\Bower\e_sqlite3.dll' "$dir\syms-{{SYMS}}" -Force -ErrorAction SilentlyContinue
$etl = "$dir\cpu-{{LABEL}}.etl"
# Windows PowerShell 5.1 turns native stderr into errors under Stop: run wpr through cmd.
cmd.exe /c 'wpr.exe -cancel >NUL 2>&1'
cmd.exe /c 'wpr.exe -start CPU -filemode >NUL 2>&1'
if ($LASTEXITCODE -ne 0) { throw "wpr start failed $LASTEXITCODE" }
$p = Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='Bower'").ProcessId
$before = $p.TotalProcessorTime.TotalSeconds
Start-Sleep -Seconds {{SECONDS}}
$p.Refresh(); $cpu = $p.TotalProcessorTime.TotalSeconds - $before
cmd.exe /c "wpr.exe -stop `"$etl`" >NUL 2>&1"
if ($LASTEXITCODE -ne 0) { throw "wpr stop failed $LASTEXITCODE" }
"label={{LABEL}} seconds={{SECONDS}} collectorCpuSeconds=$([Math]::Round($cpu,2)) cpuSecondsPerHour=$([Math]::Round($cpu*3600/{{SECONDS}},0))"
& "$dir\tool\Bower.EtlStacks.exe" $etl Bower.Collector "$dir\syms-{{SYMS}}" {{TOP}}
Remove-Item $etl* -Recurse -Force -ErrorAction SilentlyContinue
