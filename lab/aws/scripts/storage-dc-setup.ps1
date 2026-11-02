# Storage-pressure lab: promote the disposable domain controller (ws3.lab). Run through
# storage-lab.py only. The administrator password is fetched on the host and never printed.
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { @{phase='dc-setup'; state='already-domain-controller'} | ConvertTo-Json -Compress; exit 0 }
Import-Module AWSPowerShell
$secret = (Get-SECSecretValue -SecretId "bower-lab/$env:BOWER_LAB_RUN/dc-admin").SecretString
$secure = ConvertTo-SecureString $secret -AsPlainText -Force
Set-LocalUser -Name Administrator -Password $secure
Enable-LocalUser -Name Administrator
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
Install-ADDSForest -DomainName 'ws3.lab' -DomainNetbiosName 'WS3' -SafeModeAdministratorPassword $secure `
    -InstallDns -Force -NoRebootOnCompletion -WarningAction SilentlyContinue | Out-Null
Remove-Variable secret, secure
@{phase='dc-setup'; state='promoted-rebooting'} | ConvertTo-Json -Compress
exit 3010
