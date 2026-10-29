$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$modules = @(Get-Module -ListAvailable AWSPowerShell,AWS.Tools.S3,AWS.Tools.SecretsManager | Select-Object -ExpandProperty Name -Unique)
[pscustomobject]@{
  host = $env:BOWER_LAB_HOST
  computer = $env:COMPUTERNAME
  totalMemoryKiB = $os.TotalVisibleMemorySize
  freeMemoryKiB = $os.FreePhysicalMemory
  usedPercent = [math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100, 1)
  awsModules = $modules
  powershell = $PSVersionTable.PSVersion.ToString()
} | ConvertTo-Json -Compress
