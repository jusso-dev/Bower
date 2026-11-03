$ErrorActionPreference = 'Stop'
# Re-soak fault and canary agent for the Windows hosts (Wec: the MSI collector; Dc: the domain
# controller, the native 4625 source and the WEF forwarder). Rendered by lab.py; a SYSTEM task runs
# one tick a minute and at start-up, so the pre-registered fault schedule (preregistration.json)
# and the Dc canaries run with no operator session, including after the Wec reboot. Records are
# metadata only and go to the run bucket and the RunId-owned identity bucket.
#   ACTION=install|tick|status
$Action = if ($args.Count -gt 0) { $args[0] } else { '{{ACTION}}' }
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$bucket = '{{Artifacts}}'; $evidence = '{{EVIDENCE_BUCKET}}'; $region = '{{REGION}}'; $run = '{{RUN_ID}}'; $hostName = '{{HOST}}'
$start = [long]'{{RESOAK_START}}'
$dir = 'C:\BowerLab\resoak'; $root = 'C:\ProgramData\Bower'
$collectorExe = 'C:\Program Files\Bower\Bower.Collector.exe'
if ($run -cnotmatch '^bower-resoak-[0-9]{8}-[0-9]{6}$' -or $evidence -cne "$run-ids" -or $hostName -notin @('Wec', 'Dc')) { throw 'not an owned re-soak host' }
New-Item -ItemType Directory -Force $dir, "$dir\faults", "$dir\canary" | Out-Null

function Now { [DateTimeOffset]::UtcNow }
function Put($name) {
    # A failed upload never stops a tick (faults and canaries come first); the next hourly or final
    # upload sends the whole file again.
    foreach ($target in "s3://$evidence/hosts/$($hostName.ToLowerInvariant())/resoak/$name", "s3://$bucket/results/resoak/$run/$($hostName.ToLowerInvariant())/$name") {
        & $aws s3 cp "$dir\$name" $target --region $region --sse AES256 --only-show-errors
        if ($LASTEXITCODE -ne 0) { Add-Content "$dir\upload-errors.log" "$([DateTimeOffset]::UtcNow.ToString('o')) $name exit $LASTEXITCODE" }
    }
}
function Append($name, $record) { Add-Content "$dir\$name" ($record | ConvertTo-Json -Compress -Depth 6) -Encoding UTF8 }
function BootAt { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
function Collector {
    $svc = Get-CimInstance Win32_Service -Filter "Name='Bower'"
    $started = $null
    if ($svc.ProcessId) { $started = (Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue).StartTime }
    [ordered]@{ pid = $svc.ProcessId; state = $svc.State; startedAt = if ($started) { $started.ToUniversalTime().ToString('o') } else { $null } }
}
function Set-CertificatePath([string]$path) {
    $file = "$root\bower.env"
    $lines = Get-Content $file
    if (@($lines | Where-Object { $_ -like 'AZURE_CLIENT_CERTIFICATE_PATH=*' }).Count -ne 1) { throw 'certificate-path-setting-not-unique' }
    $lines = $lines | ForEach-Object { if ($_ -like 'AZURE_CLIENT_CERTIFICATE_PATH=*') { "AZURE_CLIENT_CERTIFICATE_PATH=$path" } else { $_ } }
    Set-Content $file $lines -Encoding ASCII
}
function Canary($now) {
    # One failed NTLM bind a minute with the canary account: a native 4625 the probe labels 'canary'.
    $minute = [long][Math]::Floor(($now.ToUnixTimeSeconds() - $start) / 60)
    if ($minute -lt 0 -or $minute -ge $script:plan.profile.soakSeconds / 60 -or (Test-Path "$dir\canary\$minute")) { return }
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $code = 0
    try {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection((New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier('{{DcIp}}', 389, $false, $false)))
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Ntlm
        $connection.Credential = New-Object System.Net.NetworkCredential('bower-canary', ('synthetic-invalid-' + [guid]::NewGuid().ToString('N')), 'BOWER')
        $connection.Timeout = [TimeSpan]::FromSeconds(5)
        try { $connection.Bind(); $code = -2 } catch [System.DirectoryServices.Protocols.LdapException] { $code = $_.Exception.ErrorCode } finally { $connection.Dispose() }
    } catch { $code = -1 }
    $sent = (Now).ToString('o')
    Append 'canary.jsonl' ([ordered]@{ minute = $minute; sentAt = $sent; ldapResultCode = $code })
    Set-Content "$dir\canary\$minute" $sent
}

$script:plan = Get-Content "$dir\plan.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($Action -eq 'install') {
    if (Get-ScheduledTask -TaskName 'BowerResoakAgent' -ErrorAction SilentlyContinue) { throw 'agent already installed' }
    & $aws s3 cp "s3://$bucket/artifacts/qualification/$run/sender/resoak-plan.json" "$dir\plan.json" --region $region --only-show-errors
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash "$dir\plan.json" -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{PLAN_SHA256}}') { throw 'plan digest mismatch' }
    $script:plan = Get-Content "$dir\plan.json" -Raw | ConvertFrom-Json
    if ($hostName -eq 'Wec') {
        # Pre-staged second ingestion certificate (added to the application before the run).
        & $aws s3 cp "s3://$bucket/artifacts/resoak/wec/ingest-next.pem" "$root\secrets\ingest-next.pem" --region $region --only-show-errors
        if ($LASTEXITCODE -ne 0 -or (Get-FileHash "$root\secrets\ingest-next.pem" -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{{INGEST_NEXT_SHA256}}') { throw 'ingest-next digest mismatch' }
    }
    Copy-Item $PSCommandPath "$dir\agent.ps1" -Force
    $command = "-NoProfile -ExecutionPolicy Bypass -File $dir\agent.ps1 tick"
    $next = (Get-Date).AddSeconds(60 - (Get-Date).Second)
    $triggers = @((New-ScheduledTaskTrigger -Once -At $next -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 5)),
                  (New-ScheduledTaskTrigger -AtStartup))
    Register-ScheduledTask -TaskName 'BowerResoakAgent' -User SYSTEM -RunLevel Highest -Trigger $triggers `
        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $command) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -StartWhenAvailable) | Out-Null
    [ordered]@{ installed = $true; host = $hostName; agentSha256 = (Get-FileHash "$dir\agent.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
        faults = @($script:plan.faults | Where-Object { $_.hosts -contains $hostName } | ForEach-Object { $_.id }) } | ConvertTo-Json -Compress
    exit 0
}
if ($Action -eq 'tick') {
    $now = Now
    $offset = $now.ToUnixTimeSeconds() - $start
    foreach ($fault in $script:plan.faults) {
        if ($fault.hosts -notcontains $hostName) { continue }
        $marker = "$dir\faults\$($fault.id)"
        if (Test-Path $marker) {
            $state = Get-Content $marker -Raw | ConvertFrom-Json
            if ($fault.kind -eq 'destination-outage' -and $state.step -eq 'done' -and $offset -ge $fault.at + $fault.durationSeconds -and -not (Test-Path "$marker.restored")) {
                $rule = Get-NetFirewallRule -Name "BowerResoakOutage-$($fault.id)" -ErrorAction SilentlyContinue
                $record = [ordered]@{ fault = $fault.id; step = 'restored'; at = $now.ToString('o'); bootAt = BootAt }
                if ($rule) { $rule | Remove-NetFirewallRule; $record.restoredAt = $now.ToString('o'); $record.by = 'tick' }
                elseif (Test-Path "$dir\outage-restored-$($fault.id)") { $record.restoredAt = (Get-Content "$dir\outage-restored-$($fault.id)" -Raw).Trim(); $record.by = 'task' }
                else { $record.by = 'unknown'; $record.error = 'outage-rule-missing-without-restore-record' }
                Append 'faults.jsonl' $record; Set-Content "$marker.restored" $now.ToString('o'); Put 'faults.jsonl'
            }
            if ($fault.kind -eq 'host-reboot' -and $state.step -eq 'done' -and -not (Test-Path "$marker.after") -and (BootAt) -cne $state.bootAt) {
                Append 'faults.jsonl' ([ordered]@{ fault = $fault.id; step = 'after-reboot'; at = $now.ToString('o'); bootAt = BootAt; collector = Collector })
                Set-Content "$marker.after" $now.ToString('o'); Put 'faults.jsonl'
            }
            continue
        }
        if ($offset -lt $fault.at) { continue }
        $record = [ordered]@{ fault = $fault.id; kind = $fault.kind; host = $hostName; plannedAt = $start + $fault.at; startedAt = $now.ToString('o')
            lateSeconds = $offset - $fault.at; bootAt = BootAt }
        if ($offset - $fault.at -gt 600) {
            $record.step = 'missed'
            Append 'faults.jsonl' $record; $record | ConvertTo-Json -Compress | Set-Content $marker; continue
        }
        try {
            $detail = [ordered]@{}
            switch ($fault.kind) {
                'destination-outage' {
                    $name = "BowerResoakOutage-$($fault.id)"
                    # The independent restore task is armed before the block is applied; the tick also restores.
                    $restore = "Remove-NetFirewallRule -Name '$name' -ErrorAction Stop; Set-Content '$dir\outage-restored-$($fault.id)' ([DateTimeOffset]::UtcNow.ToString('o'))"
                    Register-ScheduledTask -TaskName "BowerResoakRestore-$($fault.id)" -User SYSTEM -RunLevel Highest `
                        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$restore`"") `
                        -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds([int]$fault.durationSeconds)) `
                        -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
                    New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Program $collectorExe -Protocol TCP -RemotePort 443 | Out-Null
                    $detail.rule = $name; $detail.restoreArmedSeconds = $fault.durationSeconds
                }
                'collector-kill' { $detail.killed = Collector; Stop-Process -Id $detail.killed.pid -Force }
                'host-reboot' { $detail.collector = Collector }
                'credential-rotation-ingestion' { $detail.before = Collector; Set-CertificatePath "$root\secrets\ingest-next.pem"; Restart-Service Bower; $detail.after = Collector }
                'sender-restart' { Restart-Service WinRM -Force; $detail.winrm = (Get-Service WinRM).Status.ToString() }
                default { throw "unsupported fault kind $($fault.kind)" }
            }
            $record.step = 'done'; $record.detail = $detail; $record.endedAt = (Now).ToString('o')
        } catch { $record.step = 'failed'; $record.error = $_.Exception.GetType().Name + ':' + ($_.Exception.Message -replace '\s+', ' ').Substring(0, [Math]::Min(120, $_.Exception.Message.Length)) }
        Append 'faults.jsonl' $record
        $record | ConvertTo-Json -Compress -Depth 6 | Set-Content $marker
        Put 'faults.jsonl'
        if ($fault.kind -eq 'host-reboot' -and $record.step -eq 'done') { Restart-Computer -Force; exit 0 }
    }
    if ($hostName -eq 'Dc') { Canary $now }
    if ($now.Minute -eq 0 -or ($offset -ge $script:plan.profile.soakSeconds + 1800 -and -not (Test-Path "$dir\published"))) {
        foreach ($n in 'faults.jsonl', 'canary.jsonl') { if (Test-Path "$dir\$n") { Put $n } }
        if ($offset -ge $script:plan.profile.soakSeconds + 1800) { Set-Content "$dir\published" $now.ToString('o') }
    }
    exit 0
}
if ($Action -eq 'status') {
    Get-Content "$dir\faults.jsonl" -Tail 6 -ErrorAction SilentlyContinue
    "canaries=$(@(Get-ChildItem "$dir\canary" -ErrorAction SilentlyContinue).Count)"
    Get-Content "$dir\canary.jsonl" -Tail 1 -ErrorAction SilentlyContinue
    (Get-ScheduledTask -TaskName 'BowerResoakAgent').State
    exit 0
}
throw "unknown action $Action"
