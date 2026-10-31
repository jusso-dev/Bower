$ErrorActionPreference = 'Stop'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$plain = & $aws secretsmanager get-secret-value --secret-id '{{Secret}}' --region '{{REGION}}' --query SecretString --output text
if ($LASTEXITCODE -ne 0) { throw 'Unable to read temporary domain credential' }
$credential = New-Object PSCredential('BOWER\Administrator', (ConvertTo-SecureString $plain -AsPlainText -Force))
$plain = $null
Get-NetAdapter | Where-Object Status -eq Up | Set-DnsClientServerAddress -ServerAddresses '{{DcIp}}'
for ($i=0; $i -lt 60; $i++) {
    try {
        Resolve-DnsName _ldap._tcp.dc._msdcs.bower.test -Type SRV -Server '{{DcIp}}' -ErrorAction Stop | Out-Null
        break
    } catch { Start-Sleep -Seconds 2 }
}
Add-Computer -DomainName bower.test -Credential $credential -Force | Out-Null
Write-Output 'Domain join complete; restart scheduled.'
shutdown.exe /r /t 10 | Out-Null
