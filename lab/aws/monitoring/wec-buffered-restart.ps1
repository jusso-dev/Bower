# Short, separate populated-queue crash proof. Never run during the hourly campaign.
# run.py supplies owned run metadata; no native authentication is generated here.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Write-WecRestartJson([string]$Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 10)+"`n")
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function ConvertTo-WecRestartTimestamp($Value) {
    if($Value -is [DateTimeOffset]){return $Value}
    if($Value -is [DateTime]){
        if($Value.Kind -eq [DateTimeKind]::Unspecified){throw 'timestamp-kind'}
        return [DateTimeOffset]$Value
    }
    if($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$'){throw 'timestamp-shape'}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
}

function Get-WecRestartStatus {
    $token=[IO.File]::ReadAllText('C:\ProgramData\Bower\secrets\ingest-token').Trim()
    try{return Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{Authorization="Bearer $token"} -TimeoutSec 5}finally{$token=$null}
}

function Assert-WecRestartRule($Rule) {
    $app=$Rule|Get-NetFirewallApplicationFilter;$port=$Rule|Get-NetFirewallPortFilter
    if($Rule.Direction -ne 'Outbound' -or $Rule.Action -ne 'Block' -or $app.Program -ine 'C:\Program Files\Bower\Bower.Collector.exe' -or
        [string]$port.Protocol -notin @('TCP','6') -or [string]$port.RemotePort -ne '443'){throw 'rule-owner'}
}

function Get-WecRestartFaultState([string]$Name) {
    $state=@{active=$false;present=$false;enabled=$false;ownershipVerified=$false}
    try {
        $rules=@(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)
        $state.present=$rules.Count -eq 1
        if($state.present){
            $state.enabled=$rules[0].Enabled -eq 'True'
            Assert-WecRestartRule $rules[0];$state.ownershipVerified=$true
            $state.active=$state.enabled -and $state.ownershipVerified
        }
    }catch{$state.errorCategory=$_.Exception.GetType().Name}
    return $state
}

function Restore-WecRestartFault([string]$Root,[string]$Name,[string]$Run,[string]$Reason) {
    $record=@{runId=$Run;rule=$Name;reason=$Reason;at=[DateTimeOffset]::UtcNow.ToString('o');removed=$false;deliveryQualified=$false}
    try {
        $rule=Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
        if($rule){Assert-WecRestartRule $rule;$rule|Remove-NetFirewallRule -ErrorAction Stop}
        $record.removed=-not [bool](Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)
    }catch{$record.errorCategory=$_.Exception.GetType().Name}
    # Connectivity restoration precedes evidence writes, even if the disk is full.
    $file=Join-Path $Root ('restore-'+[guid]::NewGuid().ToString('N')+'.json')
    Write-WecRestartJson $file $record
    return $record
}

function Compare-WecRestartSnapshot($Before,$After) {
    $checks=@{}
    foreach($field in @('runId','phase','planSha256','bootId','executableSha256','sqliteSha256','environmentSha256','sourceConfigSha256','allWinevtIdsSha256','phaseIdsSha256','bookmarkRecordId','allWinevtCount','phaseCount','delivered')){
        $checks[$field]=$Before.$field -ceq $After.$field
    }
    $checks.validBookmark=$Before.bookmarkRecordId -gt 0 -and $After.bookmarkRecordId -gt 0
    $checks.faultActiveAcrossSnapshot=$After.faultActiveBeforeSnapshot -and $After.faultActiveAfterSnapshot
    $checks.phase600=$Before.phaseCount -eq 600 -and $After.phaseCount -eq 600
    $checks.pendingRetained=$Before.pending -ge 600 -and $After.pending -ge $Before.pending
    $checks.noDeadLetters=$Before.deadLettered -eq 0 -and $After.deadLettered -eq 0
    $checks.sourceHealthy=$Before.sourceHealthy -and $After.sourceHealthy
    $checks.sameService=$Before.serviceAccount -ceq 'NT SERVICE\Bower' -and $After.serviceAccount -ceq $Before.serviceAccount
    $checks.newProcess=$Before.processId -gt 0 -and $After.processId -gt 0 -and $Before.processId -ne $After.processId -and $After.processStartedTicks -gt $Before.processStartedTicks
    return @{checks=$checks;acceptedQueueRecoveryVerified=(@($checks.Values|Where-Object{$_ -ne $true}).Count -eq 0);deliveryQualified=$false;destinationQueryVerified=$false}
}

function Get-WecRestartSnapshot([string]$Phase,[string]$Plan,[string]$ExpectedExecutable,[string]$ExpectedSqlite) {
    $base='C:\ProgramData\Bower\monitoring'
    $reportPath=Join-Path $base ($Phase+'.json')
    if((Get-Item $reportPath).Length -gt 262144){throw 'phase-bound'}
    $phaseRecord=Get-Content $reportPath -Raw|ConvertFrom-Json
    if($phaseRecord.runId -cne $env:BOWER_LAB_RUN -or $phaseRecord.phase -cne $Phase -or $phaseRecord.mode -cne 'phase' -or $phaseRecord.requestedRate -ne 10 -or $phaseRecord.generator.requested -ne 600 -or
        -not $phaseRecord.nativeVerified -or $phaseRecord.native.count -ne 600 -or $phaseRecord.queueIdentities.count -ne 600 -or -not $phaseRecord.queueIdentities.exactNativeMatch){throw 'phase-not-qualified'}
    $phasePath=Join-Path $base ($Phase+'-queue.ids')
    if((Get-Item $phasePath).Length -gt 65536 -or (Get-FileHash $phasePath).Hash.ToLowerInvariant() -cne $phaseRecord.queueIdentities.idsSha256){throw 'phase-identities'}
    $expected=@([IO.File]::ReadAllLines($phasePath)|Where-Object{$_})
    if($expected.Count -ne 600 -or @($expected|Sort-Object -Unique).Count -ne 600 -or @($expected|Where-Object{$_ -cnotmatch '^winevt-[a-f0-9]{32}$'}).Count){throw 'phase-identities'}
    Add-WecQueueReader
    $rows=[BowerWecQueueMetadata]::Read('C:\ProgramData\Bower\data\bower.db')
    $ids=@($rows|ForEach-Object{$_[0]}|Sort-Object)
    if(@($ids|Sort-Object -Unique).Count -ne $ids.Count -or @($ids|Where-Object{$_ -cnotmatch '^winevt-[a-f0-9]{32}$'}).Count){throw 'queue-identities'}
    $set=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($id in $ids){[void]$set.Add($id)}
    if(@($expected|Where-Object{-not $set.Contains($_)}).Count){throw 'accepted-identity-missing'}
    $status=Get-WecRestartStatus;$sources=@($status.windowsEventLog|Where-Object{$_.id -ceq 'wec-security'})
    if($sources.Count -ne 1){throw 'source-count'};$source=$sources[0]
    $healthy=$source.state -ceq 'running' -and $source.channel -ceq 'ForwardedEvents'
    $sourceCounters=@{}
    foreach($counter in @('rejected','parserErrors','malformed','oversized','readErrors','submitFailures','gaps','resets','cursorConflicts')){$sourceCounters[$counter]=$source.$counter;if($source.$counter -ne 0){$healthy=$false}}
    $service=Get-CimInstance Win32_Service -Filter "Name='Bower'"
    if($service.State -ne 'Running' -or $service.StartName -cne 'NT SERVICE\Bower' -or $service.ProcessId -le 0){throw 'service-owner'}
    $process=Get-Process -Id $service.ProcessId
    if($process.Path -ine 'C:\Program Files\Bower\Bower.Collector.exe'){throw 'process-owner'}
    $exe=(Get-FileHash $process.Path).Hash.ToLowerInvariant()
    $sqlite=(Get-FileHash 'C:\Program Files\Bower\e_sqlite3.dll').Hash.ToLowerInvariant()
    if($exe -cne $ExpectedExecutable -or $sqlite -cne $ExpectedSqlite){throw 'candidate-changed'}
    $environment=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment)
    $hash=[Security.Cryptography.SHA256]::Create()
    try {
        $idHash=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::ASCII.GetBytes(($ids -join "`n")))).Replace('-','').ToLowerInvariant()
        $environmentHash=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($environment -join "`n")))).Replace('-','').ToLowerInvariant()
    }finally{$hash.Dispose();$environment=$null}
    $metadata=@{runId=$env:BOWER_LAB_RUN;phase=$Phase;planSha256=$Plan;at=[DateTimeOffset]::UtcNow.ToString('o');
        bootId=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');executableSha256=$exe;
        sqliteSha256=$sqlite;environmentSha256=$environmentHash;
        sourceConfigSha256=(Get-FileHash 'C:\ProgramData\Bower\windows-eventlog.json').Hash.ToLowerInvariant();
        allWinevtIdsSha256=$idHash;allWinevtCount=$ids.Count;phaseIdsSha256=$phaseRecord.queueIdentities.idsSha256;phaseCount=$expected.Count;
        bookmarkRecordId=$source.bookmarkRecordId;sourceHealthy=$healthy;sourceCounters=$sourceCounters;serviceAccount=$service.StartName;processId=$service.ProcessId;
        processStartedTicks=$process.StartTime.ToUniversalTime().Ticks;delivered=$status.queue.delivered;deadLettered=$status.queue.deadLettered;
        pending=([long]$status.queue.queued+[long]$status.queue.retrying+[long]$status.queue.uploading);
        lastSuccessfulDeliveryAt=$status.deliveryActivity.lastSuccessfulDeliveryAt;phaseStartedAt=$phaseRecord.generator.startedAt;
        destinationQueryVerified=$false;deliveryQualified=$false}
    return @{metadata=$metadata;ids=$ids}
}

function Save-WecRestartSnapshot([string]$Root,[string]$Label,$Snapshot) {
    $path=Join-Path $Root ($Label+'-winevt.ids')
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.Encoding]::ASCII.GetBytes(($Snapshot.ids -join "`n"));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if((Get-FileHash $path).Hash.ToLowerInvariant() -cne $Snapshot.metadata.allWinevtIdsSha256){throw 'snapshot-hash'}
    Write-WecRestartJson (Join-Path $Root ($Label+'.json')) $Snapshot.metadata
}

# Same bounded read-only ID/timestamp reader used by wec-qualification.ps1.
function Add-WecQueueReader {
    if ('BowerWecQueueMetadata' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BowerWecQueueMetadata {
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2([MarshalAs(UnmanagedType.LPStr)] string name, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(IntPtr db, [MarshalAs(UnmanagedType.LPStr)] string sql, int length, out IntPtr statement, IntPtr tail);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr statement);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr statement, int column);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_column_bytes(IntPtr statement, int column);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr statement);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    private static extern int sqlite3_busy_timeout(IntPtr db, int milliseconds);
    public static string[][] Read(string path) {
        IntPtr db=IntPtr.Zero, statement=IntPtr.Zero;
        try {
            // SQLITE_OPEN_READONLY. Never fetch payloads or emit native error text.
            if(sqlite3_open_v2(path,out db,1,IntPtr.Zero)!=0) throw new InvalidOperationException("queue-open");
            if(sqlite3_busy_timeout(db,10000)!=0) throw new InvalidOperationException("queue-timeout");
            const string sql="SELECT event_id, received_at FROM queue_events WHERE event_id LIKE 'winevt-%' LIMIT 200001";
            if(sqlite3_prepare_v2(db,sql,-1,out statement,IntPtr.Zero)!=0) throw new InvalidOperationException("queue-prepare");
            var rows=new List<string[]>();int code;
            while((code=sqlite3_step(statement))==100) {
                if(rows.Count>=200000 || sqlite3_column_bytes(statement,0)>128 || sqlite3_column_bytes(statement,1)>64)
                    throw new InvalidOperationException("queue-bound");
                rows.Add(new string[] {Marshal.PtrToStringAnsi(sqlite3_column_text(statement,0)),Marshal.PtrToStringAnsi(sqlite3_column_text(statement,1))});
            }
            if(code!=101) throw new InvalidOperationException("queue-read");
            return rows.ToArray();
        } finally {if(statement!=IntPtr.Zero)sqlite3_finalize(statement);if(db!=IntPtr.Zero)sqlite3_close(db);}
    }
}
'@
}



try {
    $run=$env:BOWER_LAB_RUN;$phase=$env:BOWER_WEC_PHASE;$plan=$env:BOWER_PLAN_SHA256;$exe=$env:BOWER_CANDIDATE_SHA256;$sqlite=$env:BOWER_SQLITE_SHA256;$action=$env:BOWER_WEC_RESTART_ACTION
    if($env:OS -ne 'Windows_NT' -or $run -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or $phase -cnotmatch '^[a-z][a-z0-9-]{0,39}$' -or
        $plan -cnotmatch '^[a-f0-9]{64}$' -or $exe -cnotmatch '^[a-f0-9]{64}$' -or $sqlite -cnotmatch '^[a-f0-9]{64}$' -or $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2'){throw 'scope'}
    $base='C:\ProgramData\Bower\monitoring';$config=Get-Content "$base\qualification.json" -Raw|ConvertFrom-Json
    if($config.runId -cne $run){throw 'owner'}
    $root=Join-Path $base ('buffered-restart\'+$phase);$name='BowerRecovery-'+$run+'-'+$phase
    if($action -eq 'prepare') {
        $previous=$env:BOWER_PREVIOUS_SAMPLE_SCOPE;$previousPlan=$env:BOWER_PREVIOUS_PLAN_SHA256
        if($previous -cnotmatch '^[a-z][a-z0-9-]{0,39}$' -or $previous -ceq $phase -or $previousPlan -cnotmatch '^[a-f0-9]{64}$'){throw 'predecessor'}
        $sample=Get-Content "$base\resource-samples\$run\$previous-$previousPlan\export-summary.json" -Raw|ConvertFrom-Json
        $hour=Get-Content "$base\outage-restored.json" -Raw|ConvertFrom-Json
        if(-not $sample.samplingComplete -or $sample.runId -cne $run -or $sample.scope -cne $previous -or $sample.planSha256 -cne $previousPlan -or
            $sample.durationSeconds -ne 4500 -or $sample.sampleCount -ne 301 -or $sample.failedSampleCount -ne 0 -or -not $sample.bootUnchanged -or $sample.processRestartCount -ne 0 -or -not $hour.removed -or -not $hour.minimumDurationPassed -or $hour.runId -cne $run -or
            (Get-NetFirewallRule -Name ('BowerOutage-'+$run) -ErrorAction SilentlyContinue)){throw 'hour-not-finished'}
        $status=Get-WecRestartStatus
        if($status.queue.queued -ne 0 -or $status.queue.retrying -ne 0 -or $status.queue.uploading -ne 0 -or $status.queue.deadLettered -ne 0){throw 'baseline-not-empty'}
        if((Test-Path $root) -or (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) -or (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)){throw 'scope-already-used'}
        [void](New-Item $root -ItemType Directory)
        Write-WecRestartJson "$root\scope.json" @{runId=$run;phase=$phase;planSha256=$plan;candidateSha256=$exe;sqliteSha256=$sqlite;previousSampleScope=$previous;previousPlanSha256=$previousPlan}
        $rollback="`$ErrorActionPreference='Stop'`nfunction Write-WecRestartJson {`n${function:Write-WecRestartJson}`n}`nfunction Assert-WecRestartRule {`n${function:Assert-WecRestartRule}`n}`nfunction Restore-WecRestartFault {`n${function:Restore-WecRestartFault}`n}`n`$r=Restore-WecRestartFault '$root' '$name' '$run' 'automatic-guard'`nif(-not `$r.removed){exit 1}"
        [IO.File]::WriteAllText("$root\rollback.ps1",$rollback)
        $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -File `"$root\rollback.ps1`""
        Register-ScheduledTask -TaskName $name -User SYSTEM -RunLevel Highest -Action $taskAction -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2))|Out-Null
        if((Get-ScheduledTask -TaskName $name).State -eq 'Disabled'){throw 'guard-disabled'}
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Enabled True -Profile Any -Program 'C:\Program Files\Bower\Bower.Collector.exe' -Protocol TCP -RemotePort 443|Out-Null
        $record=@{runId=$run;phase=$phase;planSha256=$plan;at=[DateTimeOffset]::UtcNow.ToString('o');rule=$name;guardSeconds=600;guardNextRunAt=(Get-ScheduledTaskInfo -TaskName $name).NextRunTime.ToUniversalTime().ToString('o');deliveryQualified=$false}
        Write-WecRestartJson "$root\fault-applied.json" $record;$record|ConvertTo-Json -Compress
    } else {
        $scope=Get-Content "$root\scope.json" -Raw|ConvertFrom-Json
        if($scope.runId -cne $run -or $scope.phase -cne $phase -or $scope.planSha256 -cne $plan -or $scope.candidateSha256 -cne $exe -or $scope.sqliteSha256 -cne $sqlite){throw 'saved-scope'}
        if($action -eq 'off') {
            $record=Restore-WecRestartFault $root $name $run 'manual-off'
            if($record.removed){Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
            $record|ConvertTo-Json -Compress;if(-not $record.removed){exit 1}
        } elseif($action -eq 'before' -or $action -eq 'crash') {
            $rule=Get-NetFirewallRule -Name $name -ErrorAction Stop;Assert-WecRestartRule $rule
            if($rule.Enabled -ne 'True'){throw 'fault-not-active'}
            # Do not interrupt a generator or its expensive native reconciliation.
            $lock=[IO.File]::Open("$base\generator.lock",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try {
                $snapshot=Get-WecRestartSnapshot $phase $plan $exe $sqlite
                if(-not $snapshot.metadata.sourceHealthy -or $snapshot.metadata.pending -lt 600 -or $snapshot.metadata.deadLettered -ne 0 -or
                    ($null -ne $snapshot.metadata.lastSuccessfulDeliveryAt -and (ConvertTo-WecRestartTimestamp $snapshot.metadata.lastSuccessfulDeliveryAt) -ge (ConvertTo-WecRestartTimestamp $snapshot.metadata.phaseStartedAt))){throw 'buffer-not-proven'}
                if($action -eq 'before'){Save-WecRestartSnapshot $root 'before' $snapshot;$snapshot.metadata|ConvertTo-Json -Depth 5 -Compress}
                else {
                    $before=Get-Content "$root\before.json" -Raw|ConvertFrom-Json
                    foreach($field in @('runId','phase','planSha256','bootId','executableSha256','sqliteSha256','environmentSha256','sourceConfigSha256','allWinevtIdsSha256','phaseIdsSha256','bookmarkRecordId','allWinevtCount','phaseCount','delivered','processId','processStartedTicks')) {
                        if($before.$field -cne $snapshot.metadata.$field){throw 'baseline-changed'}
                    }
                    Save-WecRestartSnapshot $root 'pre-kill' $snapshot
                    $crash=@{runId=$run;phase=$phase;killedPid=$snapshot.metadata.processId;killedAt=[DateTimeOffset]::UtcNow.ToString('o');recovered=$false;deliveryQualified=$false}
                    try {
                        $target=Get-Process -Id $snapshot.metadata.processId
                        $currentService=Get-CimInstance Win32_Service -Filter "Name='Bower'"
                        if($currentService.ProcessId -ne $target.Id -or $target.StartTime.ToUniversalTime().Ticks -ne $snapshot.metadata.processStartedTicks -or $target.Path -ine 'C:\Program Files\Bower\Bower.Collector.exe'){throw 'process-changed'}
                        Stop-Process -InputObject $target -Force
                        $timer=[Diagnostics.Stopwatch]::StartNew()
                        do {
                            Start-Sleep -Milliseconds 500
                            $service=Get-CimInstance Win32_Service -Filter "Name='Bower'"
                            if($service.ProcessId -gt 0 -and $service.ProcessId -ne $snapshot.metadata.processId){
                                try {
                                    Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2|Out-Null
                                    $probe=Get-WecRestartStatus
                                    $liveSources=@($probe.windowsEventLog|Where-Object{$_.id -ceq 'wec-security'})
                                    $crash.recovered=$liveSources.Count -eq 1 -and $liveSources[0].state -ceq 'running'
                                }catch{$crash.recovered=$false}
                            }
                        }while(-not $crash.recovered -and $timer.Elapsed.TotalSeconds -lt 60)
                        $crash.recoverySeconds=$timer.Elapsed.TotalSeconds
                        if(-not $crash.recovered -or $crash.recoverySeconds -gt 60){throw 'scm-recovery-timeout'}
                        $crash.faultBeforeSnapshot=Get-WecRestartFaultState $name
                        $after=Get-WecRestartSnapshot $phase $plan $exe $sqlite
                        $crash.faultAfterSnapshot=Get-WecRestartFaultState $name
                        $after.metadata.faultActiveBeforeSnapshot=$crash.faultBeforeSnapshot.active
                        $after.metadata.faultActiveAfterSnapshot=$crash.faultAfterSnapshot.active
                        Save-WecRestartSnapshot $root 'after' $after
                        $crash.verification=Compare-WecRestartSnapshot $snapshot.metadata $after.metadata
                        if(-not $crash.verification.acceptedQueueRecoveryVerified){throw 'recovery-proof-failed'}
                    }catch{$crash.errorCategory=$_.Exception.GetType().Name}
                    finally {
                        $crash.restoration=Restore-WecRestartFault $root $name $run 'crash-finally'
                        if($crash.restoration.removed){Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
                        Write-WecRestartJson "$root\crash.json" $crash
                    }
                    $crash|ConvertTo-Json -Depth 8 -Compress
                    if(-not $crash.ContainsKey('verification') -or -not $crash.verification.acceptedQueueRecoveryVerified -or -not $crash.restoration.removed){exit 1}
                }
            }finally{$lock.Dispose()}
        } elseif($action -eq 'export') {
            if($env:BOWER_LAB_BUCKET -cnotmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'){throw 'bucket'}
            $exports=@()
            foreach($file in Get-ChildItem $root -File|Where-Object{$_.Name -match '^(scope|fault-applied|before|pre-kill|after|crash|restore-[a-f0-9]{32})\.json$|^(before|pre-kill|after)-winevt\.ids$'}){
                if($file.Length -gt 8388608 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'export-bound'}
                $digest=(Get-FileHash $file.FullName).Hash.ToLowerInvariant();$bytes=$file.Length
                $key="results/qualification/$run/windows/$phase/restart/$($file.Name)"
                & 'C:\Program Files\Amazon\AWSCLIV2\aws.exe' s3 cp $file.FullName "s3://$($env:BOWER_LAB_BUCKET)/$key" --sse AES256 --only-show-errors *> $null
                if($LASTEXITCODE -ne 0 -or (Get-FileHash $file.FullName).Hash.ToLowerInvariant() -cne $digest -or (Get-Item $file.FullName).Length -ne $bytes){throw 'export-changed'}
                $exports+=@{key=$key;bytes=$bytes;sha256=$digest}
            }
            @{runId=$run;phase=$phase;exports=$exports;deliveryQualified=$false}|ConvertTo-Json -Depth 5 -Compress
        } else {throw 'action'}
    }
}catch{@{restartProof='failed';exceptionType=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;deliveryQualified=$false}|ConvertTo-Json -Compress;exit 1}
