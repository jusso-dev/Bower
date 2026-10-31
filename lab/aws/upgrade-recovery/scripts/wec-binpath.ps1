$ErrorActionPreference = 'Stop'
# Points the MSI-installed service at a binary: 'legacy' (side-loaded 74e250f build, v1 bookmarks) or 'msi'.
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
if ('{{TARGET}}' -eq 'legacy') {
    if (!(Test-Path C:\BowerLab\legacy\Bower.Collector.exe)) { Expand-Archive C:\BowerLab\artifacts\legacy-74e250f-win-x64.zip -DestinationPath C:\BowerLab\legacy -Force }
    $path = 'C:\BowerLab\legacy\Bower.Collector.exe'
} else { $path = 'C:\Program Files\Bower\Bower.Collector.exe' }
Stop-Service Bower -ErrorAction SilentlyContinue
sc.exe config Bower binPath= "`"$path`"" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc config failed' }
Start-Service Bower
Start-Sleep -Seconds 8
$s = Get-CimInstance Win32_Service -Filter "Name='Bower'"
[ordered]@{ target = '{{TARGET}}'; state = $s.State; path = $s.PathName; sha256 = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(); at = [DateTimeOffset]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
