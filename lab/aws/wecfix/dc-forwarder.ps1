$ErrorActionPreference = 'Stop'
# The DC forwards its Security 4625 events to both WEC hosts (source-initiated), so the new
# and the old Bower build read identical ForwardedEvents channels on identical hardware.
winrm.cmd quickconfig -q | Out-Null
Set-Service WinRM -StartupType Automatic
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name '1' -Value 'Server=http://BOWERWEC.bower.test:5985/wsman/SubscriptionManager/WEC,Refresh=10' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name '2' -Value 'Server=http://BOWERWEC2.bower.test:5985/wsman/SubscriptionManager/WEC,Refresh=10' -PropertyType String -Force | Out-Null
$channel = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
if ($channel.SecurityDescriptor -notmatch '\(A;;0x1;;;NS\)') {
    $channel.SecurityDescriptor += '(A;;0x1;;;NS)'
    $channel.SaveChanges()
}
$channel.Dispose()
auditpol.exe /set /subcategory:Logon /failure:enable | Out-Null
wevtutil.exe sl Security /ms:4294967296
wevtutil.exe sl Microsoft-Windows-Forwarding/Operational /e:true
if ($LASTEXITCODE -ne 0) { throw 'Unable to enable forwarding diagnostics' }
Restart-Service WinRM
Write-Output 'Security 4625 forwarding to BOWERWEC and BOWERWEC2 configured with Network Service read access.'
