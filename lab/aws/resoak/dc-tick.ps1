$ErrorActionPreference = 'Stop'
# Run one tick of the installed DC soak agent now (uploads generator records and closed native windows).
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BowerLab\soak\agent.ps1 tick
if ($LASTEXITCODE -ne 0) { throw "agent tick exit $LASTEXITCODE" }
Get-ChildItem C:\BowerLab\soak\gen -Recurse -Filter *.json | ForEach-Object { "$($_.Directory.Name)/$($_.Name)" }
