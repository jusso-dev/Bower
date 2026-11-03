$ErrorActionPreference = 'Stop'
# Readiness probe after a reboot: prints the boot time only.
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
