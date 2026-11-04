$ErrorActionPreference = 'Stop'
# Counts (metadata only) of the collector's own log events since FROM (epoch): event id per
# hour, and how many of 1002/1009 name SqliteException. Never prints message text.
$from = [DateTimeOffset]::FromUnixTimeSeconds({{FROM}}).UtcDateTime
# Filter on UTC here: FilterHashtable StartTime is interpreted in local time.
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.Collector' } -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated.ToUniversalTime() -ge $from })
$byId = [ordered]@{}
foreach ($group in ($events | Group-Object Id | Sort-Object { [int]$_.Name })) { $byId[$group.Name] = $group.Count }
$hourly = [ordered]@{}
foreach ($group in ($events | Where-Object { $_.Id -in 1002, 1009, 1201, 1001 } | Group-Object { '{0:yyyy-MM-ddTHH}:00Z/{1}' -f $_.TimeCreated.ToUniversalTime(), $_.Id } | Sort-Object Name)) { $hourly[$group.Name] = $group.Count }
[ordered]@{
    host = $env:COMPUTERNAME; from = $from.ToString('o'); total = $events.Count; byEventId = $byId
    sqliteExceptionLoopFailures = @($events | Where-Object { $_.Id -eq 1002 -and $_.Message -match 'SqliteException' }).Count
    queueBusyBackoffs = @($events | Where-Object { $_.Id -eq 1009 }).Count
    retentionPurges = @($events | Where-Object { $_.Id -eq 1201 } | ForEach-Object { [ordered]@{ at = $_.TimeCreated.ToUniversalTime().ToString('o'); count = $(if ($_.Message -match 'removed (\d+) acknowledged') { [int]$Matches[1] } else { $null }) } })
    hourlyByEventId = $hourly
} | ConvertTo-Json -Depth 4
