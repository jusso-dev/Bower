$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force C:\BowerLab | Out-Null
if (!(Test-Path 'C:\Program Files\Amazon\AWSCLIV2\aws.exe')) {
    Invoke-WebRequest https://awscli.amazonaws.com/AWSCLIV2.msi -OutFile C:\BowerLab\aws.msi
    $install = Start-Process msiexec.exe -ArgumentList '/i C:\BowerLab\aws.msi /qn' -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw 'AWS CLI installation failed' }
    Remove-Item C:\BowerLab\aws.msi
}
$name = 'BOWER{{HOST}}'.ToUpperInvariant()
if ($env:COMPUTERNAME -ne $name) {
    Rename-Computer -NewName $name -Force
    shutdown.exe /r /t 10 | Out-Null
}
Write-Output 'Bootstrap complete; hostname restart scheduled.'
