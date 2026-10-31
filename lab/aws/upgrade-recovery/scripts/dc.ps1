$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$plain = & $aws secretsmanager get-secret-value --secret-id '{{Secret}}' --region '{{REGION}}' --query SecretString --output text
if ($LASTEXITCODE -ne 0) { throw 'Unable to read temporary domain credential' }
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
$plain = $null
Set-LocalUser -Name Administrator -Password $secure
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
Install-ADDSForest -DomainName bower.test -DomainNetbiosName BOWER -InstallDns -SafeModeAdministratorPassword $secure -Force -NoRebootOnCompletion | Out-Null
Write-Output 'Isolated domain configured; restart scheduled.'
shutdown.exe /r /t 10 | Out-Null
