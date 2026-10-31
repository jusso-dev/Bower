$ErrorActionPreference="Continue"
Get-WinEvent -LogName Microsoft-Windows-Forwarding/Operational -MaxEvents 6 | ForEach-Object { "$($_.TimeCreated.ToUniversalTime().ToString("o")) $($_.Id) $($_.Message.Substring(0,[Math]::Min(250,$_.Message.Length)))" }
