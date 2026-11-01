# App-scoped Windows firewall fault. Invoke through the owned SSM runner.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-WecOutageClock {
    return @{ utc = [DateTimeOffset]::UtcNow.ToString('o'); ticks = [Diagnostics.Stopwatch]::GetTimestamp();
        frequency = [Diagnostics.Stopwatch]::Frequency;
        boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
}

function Assert-WecOutageRule($Rule, [string]$Program) {
    $app = $Rule | Get-NetFirewallApplicationFilter
    $port = $Rule | Get-NetFirewallPortFilter
    if ($Rule.Direction -ne 'Outbound' -or $Rule.Action -ne 'Block' -or $app.Program -ine $Program -or
        [string]$port.Protocol -notin @('TCP', '6') -or [string]$port.RemotePort -ne '443') { throw 'unexpected-existing-rule' }
}

function Invoke-WecOutageRestore([string]$Root, [string]$Name, [string]$RunId, [string]$Action) {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $record = @{ runId = $RunId; action = $Action; name = $Name; removed = $false;
        minimumDurationPassed = $false; deliveryQualified = $false }
    try {
        $clock = Get-WecOutageClock
        $record.at = $clock.utc
        $record.restoreStartedTicks = $clock.ticks
        $rule = Get-NetFirewallRule -Name $Name -ErrorAction Stop
        Assert-WecOutageRule $rule 'C:\Program Files\Bower\Bower.Collector.exe'
        if ($rule.Enabled -ne 'True') { throw 'outage-rule-disabled' }
        $rule | Remove-NetFirewallRule -ErrorAction Stop
        if (Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue) { throw 'outage-rule-remains' }
        $record.removed = $true
        $record.restoredAt = [DateTimeOffset]::UtcNow.ToString('o')
        $record.restoredTicks = [Diagnostics.Stopwatch]::GetTimestamp()
        # Restoration must succeed even if writing the applied evidence failed.
        # Missing evidence invalidates qualification, never leaves egress blocked.
        $applied = Get-Content "$Root\outage-applied.json" -Raw | ConvertFrom-Json
        if ($applied.runId -cne $RunId -or $applied.name -cne $Name) { throw 'outage-evidence-owner' }
        $record.bootUnchanged = $clock.boot -ceq $applied.clock.boot
        $record.clockFrequencyUnchanged = $clock.frequency -eq $applied.clock.frequency
        $record.blockedSecondsLowerBound = ($clock.ticks - $applied.clock.ticks) / [double]$clock.frequency
        $record.minimumDurationPassed = ($record.bootUnchanged -and $record.clockFrequencyUnchanged -and
            $record.blockedSecondsLowerBound -ge 3600)
    } catch { $record.errorCategory = $_.Exception.GetType().Name }
    # This independently executed SYSTEM task writes its actual outcome, including
    # missing/changed rules and early restoration. No native error bodies are retained.
    $record | ConvertTo-Json -Depth 5 -Compress | Add-Content "$Root\outage.jsonl" -Encoding UTF8
    $record | ConvertTo-Json -Depth 5 | Set-Content "$Root\outage-restored.json" -Encoding UTF8
    return $record
}

try {
    $root = 'C:\ProgramData\Bower\monitoring'
    $config = Get-Content "$root\qualification.json" -Raw | ConvertFrom-Json
    if ($env:OS -ne 'Windows_NT' -or $env:BOWER_LAB_RUN -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or
        $config.runId -cne $env:BOWER_LAB_RUN) { throw 'owned-config' }
    $name = 'BowerOutage-' + $config.runId
    $program = 'C:\Program Files\Bower\Bower.Collector.exe'
    $action = $env:BOWER_WEC_OUTAGE_ACTION
    $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($rule) { Assert-WecOutageRule $rule $program }
    if ($action -eq 'on') {
        if ($rule -or (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
            (Test-Path "$root\outage-applied.json")) { throw 'outage-already-exists' }
        # Serialize only reviewed functions and public owned identifiers. The file
        # inherits SYSTEM/admin-only write permissions from the monitoring root.
        $rollbackSource = "`$ErrorActionPreference = 'Stop'`n" +
            "function Get-WecOutageClock {`n${function:Get-WecOutageClock}`n}`n" +
            "function Assert-WecOutageRule {`n${function:Assert-WecOutageRule}`n}`n" +
            "function Invoke-WecOutageRestore {`n${function:Invoke-WecOutageRestore}`n}`n" +
            "`$record = Invoke-WecOutageRestore '$root' '$name' '$($config.runId)' 'automatic-off'`n" +
            "if (-not `$record.removed) { exit 1 }`n"
        $rollbackSource | Set-Content "$root\outage-rollback.ps1" -Encoding UTF8
        $rollback = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -File `"$root\outage-rollback.ps1`""
        Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest -Action $rollback `
            -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(70)) `
            -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
        $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
        if ($task.State -eq 'Disabled') { throw 'restoration-task-disabled' }
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Enabled True `
            -Profile Any -Program $program -Protocol TCP -RemotePort 443 | Out-Null
        $clock = Get-WecOutageClock
        $record = @{ runId = $config.runId; action = 'on'; name = $name; at = $clock.utc; clock = $clock;
            enabled = $true; guardTask = $name; destinationFailureObserved = $false; deliveryQualified = $false }
        $record | ConvertTo-Json -Depth 5 | Set-Content "$root\outage-applied.json" -Encoding UTF8
        $record | ConvertTo-Json -Depth 5 -Compress | Add-Content "$root\outage.jsonl" -Encoding UTF8
    } elseif ($action -eq 'off') {
        if ($rule) { $record = Invoke-WecOutageRestore -Root $root -Name $name -RunId $config.runId -Action 'off' }
        else {
            # An automatic/already completed restoration must not overwrite its
            # actual duration with a later manual cleanup timestamp.
            $record = Get-Content "$root\outage-restored.json" -Raw | ConvertFrom-Json
            if ($record.runId -cne $config.runId -or $record.name -cne $name) { throw 'restoration-evidence-owner' }
        }
        if (-not $record.removed) { throw 'outage-restoration-not-proved' }
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    } elseif ($action -eq 'status') {
        $clock = Get-WecOutageClock
        $record = @{ runId = $config.runId; action = 'status'; name = $name; at = $clock.utc; clock = $clock;
            enabled = [bool]($rule -and $rule.Enabled -eq 'True'); destinationFailureObserved = $false; deliveryQualified = $false }
        $record | ConvertTo-Json -Depth 5 -Compress | Add-Content "$root\outage.jsonl" -Encoding UTF8
    } else { throw 'outage-action' }
    $record | ConvertTo-Json -Depth 5 -Compress
} catch { Write-Output '{"outage":"failed","deliveryQualified":false}'; exit 1 }
