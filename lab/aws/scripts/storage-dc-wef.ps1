# Storage-pressure lab: make the domain controller a WEF source for WEC (Security 4625 only).
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
winrm quickconfig -quiet | Out-Null
auditpol /set /subcategory:"Logon" /failure:enable | Out-Null
auditpol /set /subcategory:"Credential Validation" /failure:enable | Out-Null
Add-ADGroupMember -Identity 'Event Log Readers' -Members (Get-ADComputer $env:COMPUTERNAME) -ErrorAction SilentlyContinue
net localgroup "Event Log Readers" "NETWORK SERVICE" /add 2>$null | Out-Null
# Security log readable by the forwarding (Network Service) account.
$sddl = (wevtutil gl Security | Select-String '^channelAccess:').ToString().Split(' ',2)[1].Trim()
if ($sddl -notmatch '\(A;;0x1;;;S-1-5-20\)') { wevtutil sl Security "/ca:$sddl(A;;0x1;;;S-1-5-20)" }
wevtutil sl Security /ms:1073741824
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name '1' -Value 'Server=http://wec.ws3.lab:5985/wsman/SubscriptionManager/WEC,Refresh=60' -PropertyType String -Force | Out-Null
# A nonexistent synthetic account family cannot lock out a real account.
Restart-Service WinRM
gpupdate /target:computer /force | Out-Null
@{phase='dc-wef'; computer=$env:COMPUTERNAME; securityMaxBytes=(Get-WinEvent -ListLog Security).MaximumSizeInBytes} | ConvertTo-Json -Compress
