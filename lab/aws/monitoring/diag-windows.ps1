# Recent Bower service and collector events (metadata only).
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.Collector', '.NET Runtime', 'Application Error'; StartTime = (Get-Date).AddMinutes(-30) } -MaxEvents 8 -ErrorAction SilentlyContinue |
    ForEach-Object { "{0:o} {1} {2}: {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(500, $_.Message.Length)) }
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-30) } -MaxEvents 6 -ErrorAction SilentlyContinue |
    ForEach-Object { "{0:o} SCM {1}: {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }
"service: $((Get-Service Bower).Status)"
& wecutil.exe gr bower-forwarded | Select-String 'RunTimeStatus|LastError|ErrorMessage' | ForEach-Object { $_.Line.Trim() }
