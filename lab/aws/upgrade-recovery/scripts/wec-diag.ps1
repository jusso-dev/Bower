$ErrorActionPreference='Continue'
$f = Get-WinEvent -ListLog ForwardedEvents; "ForwardedEvents records=$($f.RecordCount)"
wecutil.exe gr Bower-Security-4625 | Select-Object -First 25
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Bower.Collector'} -MaxEvents 6 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated.ToUniversalTime().ToString('o')) $($_.LevelDisplayName): $($_.Message.Substring(0, [Math]::Min(500, $_.Message.Length)))" }
(Get-WinEvent -LogName ForwardedEvents -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object RecordId, Id, MachineName, TimeCreated | ConvertTo-Json -Compress)
