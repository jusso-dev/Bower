# Read-only operational metadata; never changes the firewall or claims destination delivery.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function ConvertTo-WecOutageTimestamp($Value) {
    if($Value -is [DateTimeOffset]){return $Value}
    if($Value -is [DateTime]){
        if($Value.Kind -eq [DateTimeKind]::Unspecified){throw 'timestamp-kind'}
        return [DateTimeOffset]$Value
    }
    if($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$'){throw 'timestamp-shape'}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
}

function Get-WecOutageReadiness($Generator, $Before, $After, $Queue, $Activity, $Applied,
    [bool]$RuleEnabled, [string]$BootId, [long]$Ticks, [long]$Frequency) {
    $result=@{readyForManualRestore=$false;validationError=$null;checks=@{}}
    try {
        $g=$Generator
        $pending=[long]$Queue.queued+[long]$Queue.retrying+[long]$Queue.uploading
        $delta=[long]$After.queued-[long]$Before.queued
        if($Frequency -le 0){throw 'clock-frequency'}
        $blocked=($Ticks-[long]$Applied.clock.ticks)/[double]$Frequency
        $failureObserved=$null -ne $Activity.lastFailureAt -and $null -ne $Activity.lastFailureCode -and
            (ConvertTo-WecOutageTimestamp $Activity.lastFailureAt) -ge (ConvertTo-WecOutageTimestamp $Applied.clock.utc)
        $noMeasuredSuccess=$null -eq $Activity.lastSuccessfulDeliveryAt -or
            (ConvertTo-WecOutageTimestamp $Activity.lastSuccessfulDeliveryAt) -lt (ConvertTo-WecOutageTimestamp $g.startedAt)
        $errorsUnchanged=$true
        foreach($field in @('rejected','parserErrors','malformed','oversized','gaps','resets','cursorConflicts')) {
            if([long]$Before.$field -lt 0 -or $After.$field -ne $Before.$field){$errorsUnchanged=$false}
        }
        $codes=@($g.resultCodes.PSObject.Properties)
        $cleanup=@($g.sessionCleanupCodes.PSObject.Properties)
        $expectedWorkers=4;$expectedCleanup=4
        if($g.credentialIsolation -eq 'per-phase-logon-new-credentials'){$expectedWorkers=64;$expectedCleanup=1}
        $cleanupCount=0;$cleanupCodesValid=$true
        foreach($entry in $cleanup){if($entry.Name -notin @('0','2250') -or $entry.Value -lt 1){$cleanupCodesValid=$false};$cleanupCount += $entry.Value}
        $sessionErrorsZero=$true
        foreach($field in @('sessionSetupFailures','impersonationFailures','revertFailures','handleCloseFailures','sessionCleanupFailures')){if($g.$field -ne 0){$sessionErrorsZero=$false}}
        $elapsed=((ConvertTo-WecOutageTimestamp $g.endedAt)-(ConvertTo-WecOutageTimestamp $g.startedAt)).TotalSeconds
        $checks=@{
            faultActive=$RuleEnabled
            clockAndDuration=($BootId -ceq $Applied.clock.boot -and $Frequency -eq $Applied.clock.frequency -and $blocked -ge 3600)
            measurementInsideFault=((ConvertTo-WecOutageTimestamp $g.startedAt) -ge (ConvertTo-WecOutageTimestamp $Applied.clock.utc))
            destinationFailureObserved=[bool]$failureObserved
            noMeasuredSuccessfulDelivery=[bool]$noMeasuredSuccess
            exactAttemptCount=($g.requested -eq 36000 -and $g.scheduled -eq 36000 -and $g.completed -eq 36000 -and $g.unexpectedSuccesses -eq 0 -and $codes.Count -eq 1 -and $codes[0].Name -ceq '1326' -and $codes[0].Value -eq 36000)
            generationRateAndDuration=($g.seconds -ge 3599.9 -and $g.seconds -le 3635 -and $g.actualRate -ge 9.9 -and $g.actualRate -le 10.1 -and [Math]::Abs(36000/[double]$g.seconds-[double]$g.actualRate) -le 0.01 -and [Math]::Abs($elapsed-[double]$g.seconds) -le 1)
            initializedAndDrained=($g.initialized -and $g.drained -and -not $g.cancelled -and $g.warmupRequired -and $g.warmupVerified -and $g.activeAtReturn -eq 0 -and $g.workersRemainingAtReturn -eq 0)
            ownedNativeSessions=($g.executionKind -ceq 'native-windows' -and $g.credentialMode -ceq 'explicit-stable-per-phase' -and $g.credentialIsolation -in @('per-phase-logon-new-credentials','per-worker-logon-new-credentials','per-process-logon-new-credentials') -and $g.workerCount -eq $expectedWorkers -and $cleanupCodesValid -and $cleanupCount -eq $expectedCleanup -and $sessionErrorsZero -and @($g.initializationFailureReasons.PSObject.Properties).Count -eq 0 -and @($g.sessionResultCodes.PSObject.Properties).Count -eq 0)
            sourceHealthy=($Before.id -ceq 'wec-security' -and $After.id -ceq 'wec-security' -and $Before.channel -ceq 'ForwardedEvents' -and $After.channel -ceq 'ForwardedEvents' -and $Before.state -ceq 'running' -and $After.state -ceq 'running' -and $errorsUnchanged)
            exactAdmission=($delta -eq 36000)
            bufferedWorkload=($Queue.queued -ge 0 -and $Queue.retrying -ge 0 -and $Queue.uploading -ge 0 -and $pending -ge 36000 -and $Queue.deadLettered -eq 0)
        }
        $result.checks=$checks;$result.admittedDelta=$delta;$result.pendingCount=$pending;$result.blockedSecondsLowerBound=$blocked
        $result.readyForManualRestore=@($checks.Values | Where-Object {$_ -ne $true}).Count -eq 0
    } catch {$result.validationError=$_.Exception.GetType().Name}
    return $result
}

try {
    $root='C:\ProgramData\Bower\monitoring'
    $config=Get-Content "$root\qualification.json" -Raw|ConvertFrom-Json
    $phase=$env:BOWER_WEC_PHASE
    if($config.runId -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or $config.runId -cne $env:BOWER_LAB_RUN -or $phase -cnotmatch '^[a-z][a-z0-9-]{0,39}$'){throw 'scope'}
    $token=[IO.File]::ReadAllText('C:\ProgramData\Bower\secrets\ingest-token').Trim()
    try {$status=Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{Authorization="Bearer $token"} -TimeoutSec 10} finally {$token=$null}
    $sources=@($status.windowsEventLog|Where-Object {$_.id -eq 'wec-security'})
    if($sources.Count -ne 1 -or $sources[0].state -ne 'running'){throw 'source'}
    $source=$sources[0];$sourceMetadata=@{};$queue=@{}
    foreach($field in @('queued','rejected','parserErrors','malformed','oversized','gaps','resets','cursorConflicts','bookmarkRecordId')){$sourceMetadata[$field]=$source.$field}
    foreach($field in @('queued','retrying','uploading','delivered','deadLettered','totalBytes','undeliveredBytes')){$queue[$field]=$status.queue.$field}
    $pending=[long]$queue.queued+[long]$queue.retrying+[long]$queue.uploading
    $activity=$status.deliveryActivity
    $failureCode=$activity.lastFailureCode
    if($null -ne $failureCode -and $failureCode -cnotmatch '^[A-Za-z0-9._-]{1,80}$'){throw 'failure-code'}
    $rule=Get-NetFirewallRule -Name ('BowerOutage-'+$config.runId) -ErrorAction SilentlyContinue
    $enabled=[bool]($rule -and $rule.Enabled -eq 'True')
    if($rule){
        $app=$rule|Get-NetFirewallApplicationFilter;$port=$rule|Get-NetFirewallPortFilter
        if($rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or $app.Program -ine 'C:\Program Files\Bower\Bower.Collector.exe' -or [string]$port.RemotePort -ne '443' -or [string]$port.Protocol -notin @('TCP','6')){throw 'rule-owner'}
    }
    $report=@{runId=$config.runId;phase=$phase;at=[DateTimeOffset]::UtcNow.ToString('o');bootId=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');source=$sourceMetadata;queue=$queue;pendingCount=$pending;ruleEnabled=$enabled;lastFailureCode=$failureCode;lastFailureAt=$activity.lastFailureAt;lastSuccessfulDeliveryAt=$activity.lastSuccessfulDeliveryAt;generatorAvailable=$false;readyForManualRestore=$false;destinationFailureObserved=$false;destinationQueryVerified=$false}
    if(Test-Path "$root\outage-applied.json") {
        $fault=Get-Content "$root\outage-applied.json" -Raw|ConvertFrom-Json
        if($fault.runId -cne $config.runId){throw 'outage-owner'}
        if($null -ne $activity.lastFailureAt -and $null -ne $failureCode){$report.destinationFailureObserved=(ConvertTo-WecOutageTimestamp $activity.lastFailureAt) -ge (ConvertTo-WecOutageTimestamp $fault.clock.utc)}
    }
    $phasePath=Join-Path $root ($phase+'.json');$checkpointPath=Join-Path $root ($phase+'-generator.json')
    if((Test-Path $phasePath) -and (Test-Path $checkpointPath)){
        if((Get-Item $phasePath).Length -gt 262144 -or (Get-Item $checkpointPath).Length -gt 32768){throw 'phase-bound'}
        $phaseRecord=Get-Content $phasePath -Raw|ConvertFrom-Json;$checkpoint=Get-Content $checkpointPath -Raw|ConvertFrom-Json
        if($phaseRecord.mode -cne 'phase' -or $phaseRecord.requestedRate -ne 10 -or $phaseRecord.runId -cne $config.runId -or $phaseRecord.phase -cne $phase -or $checkpoint.runId -cne $config.runId -or $checkpoint.phase -cne $phase){throw 'phase-owner'}
        $g=$checkpoint.generator
        $applied=Get-Content "$root\outage-applied.json" -Raw|ConvertFrom-Json
        if($applied.runId -cne $config.runId){throw 'outage-owner'}
        $readiness=Get-WecOutageReadiness $g $phaseRecord.sourceBefore $source $queue $activity $applied $enabled $report.bootId ([Diagnostics.Stopwatch]::GetTimestamp()) ([Diagnostics.Stopwatch]::Frequency)
        $report.generatorAvailable=$true;$report.generatorCompleted=$g.completed;$report.generatorRequested=$g.requested;$report.generatorRate=$g.actualRate;$report.generatorEndedAt=$g.endedAt
        $report.readiness=$readiness;$report.readyForManualRestore=$readiness.readyForManualRestore

    }
    $report|ConvertTo-Json -Depth 6 -Compress
} catch {@{observation='failed';exceptionType=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress;exit 1}
