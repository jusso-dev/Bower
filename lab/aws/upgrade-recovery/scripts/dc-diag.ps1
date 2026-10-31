$ErrorActionPreference='Continue'
Get-Content C:\BowerLab\gen\w-main.json -ErrorAction SilentlyContinue
(Get-ScheduledTask -TaskName BowerGen-w-main | Get-ScheduledTaskInfo | Select-Object LastRunTime,LastTaskResult | ConvertTo-Json -Compress)
$e = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3 -ErrorAction SilentlyContinue)
"4625 sample count=$($e.Count)"
foreach ($x in $e) { $xml=[xml]$x.ToXml(); $d=@{}; foreach($n in $xml.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "rec=$($x.RecordId) type=$($d.LogonType) ip=$($d.IpAddress) user=$($d.TargetUserName.Length)" }
Get-WinEvent -LogName Microsoft-Windows-Forwarding/Operational -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id) $($_.Message.Substring(0,[Math]::Min(300,$_.Message.Length)))" }
auditpol /get /subcategory:Logon
