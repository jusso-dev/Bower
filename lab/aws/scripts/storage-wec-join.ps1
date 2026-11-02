# Storage-pressure lab: join the WEC/collector host to ws3.lab. Run through storage-lab.py.
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
if ($env:BOWER_DC_IP -notmatch '^172\.31\.233\.\d{1,3}$') { throw 'Unexpected domain controller address' }
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { @{phase='wec-join'; state='joined'} | ConvertTo-Json -Compress; exit 0 }
Import-Module AWSPowerShell
$adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $env:BOWER_DC_IP
$secure = ConvertTo-SecureString (Get-SECSecretValue -SecretId "bower-lab/$env:BOWER_LAB_RUN/dc-admin").SecretString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('WS3\Administrator', $secure)
Add-Computer -DomainName 'ws3.lab' -NewName 'WEC' -Credential $credential -Force -WarningAction SilentlyContinue
Remove-Variable secure, credential
@{phase='wec-join'; state='joined-rebooting'} | ConvertTo-Json -Compress
exit 3010
