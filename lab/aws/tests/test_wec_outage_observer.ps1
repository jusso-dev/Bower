# Operational readiness projection only; no HTTP, firewall, Windows, or cloud calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../monitoring/observe-wec-outage.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse'}
foreach($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($function.Extent.Text))}
$source=@{id='wec-security';channel='ForwardedEvents';state='running';queued=100;rejected=0;parserErrors=0;malformed=0;oversized=0;gaps=0;resets=0;cursorConflicts=0}
$after=$source.Clone();$after.queued=36100
$template=@{
    generator=@{requested=36000;scheduled=36000;completed=36000;unexpectedSuccesses=0;resultCodes=@{'1326'=36000};seconds=3600.0;actualRate=10.0;startedAt='2026-11-01T03:47:30Z';endedAt='2026-11-01T04:47:30Z';initialized=$true;drained=$true;cancelled=$false;warmupRequired=$true;warmupVerified=$true;activeAtReturn=0;workersRemainingAtReturn=0;executionKind='native-windows';credentialMode='explicit-stable-per-phase';credentialIsolation='per-process-logon-new-credentials';workerCount=4;sessionCleanupCodes=@{'2250'=4};sessionSetupFailures=0;impersonationFailures=0;revertFailures=0;handleCloseFailures=0;sessionCleanupFailures=0;initializationFailureReasons=@{};sessionResultCodes=@{}}
    before=$source;after=$after;queue=@{queued=35000;retrying=1100;uploading=0;deadLettered=0}
    activity=@{lastFailureAt='2026-11-01T04:47:00Z';lastFailureCode='delivery-failure';lastSuccessfulDeliveryAt='2026-11-01T03:45:00Z'}
    applied=@{clock=@{ticks=0;frequency=1000;boot='boot-one';utc='2026-11-01T03:46:15Z'}}
    rule=$true;boot='boot-one';ticks=3680000;frequency=1000
} | ConvertTo-Json -Depth 10
function Get-Fixture {return ($template|ConvertFrom-Json)}
function Invoke-Readiness($Fixture) {Get-WecOutageReadiness $Fixture.generator $Fixture.before $Fixture.after $Fixture.queue $Fixture.activity $Fixture.applied $Fixture.rule $Fixture.boot $Fixture.ticks $Fixture.frequency}
$checks=0
$f=Get-Fixture;$result=Invoke-Readiness $f
if(-not $result.readyForManualRestore -or $result.admittedDelta -ne 36000 -or $result.pendingCount -ne 36100){throw 'valid readiness'};$checks++
foreach($fixtureProfile in @('per-phase-logon-new-credentials','per-worker-logon-new-credentials')){
    $f=Get-Fixture;$f.generator.credentialIsolation=$fixtureProfile
    if($fixtureProfile -eq 'per-phase-logon-new-credentials'){$f.generator.workerCount=64;$f.generator.sessionCleanupCodes.'2250'=1}
    if(-not (Invoke-Readiness $f).readyForManualRestore){throw 'valid owned profile'};$checks++
}
$changes=@(
    @{path='rule';value=$false},@{path='boot';value='other'},@{path='ticks';value=3599000},@{path='frequency';value=0},@{path='frequency';value=2000},
    @{path='activity.lastFailureAt';value=$null},@{path='activity.lastFailureAt';value='2026-11-01T03:45:00Z'},@{path='activity.lastSuccessfulDeliveryAt';value='2026-11-01T04:00:00Z'},
    @{path='generator.completed';value=35999},@{path='generator.scheduled';value=35999},@{path='generator.unexpectedSuccesses';value=1},
    @{path='generator.seconds';value=3599},@{path='generator.seconds';value=3636},@{path='generator.seconds';value=[double]::NaN},@{path='generator.actualRate';value=9.8},@{path='generator.actualRate';value=10.5},@{path='generator.endedAt';value='2026-11-01T04:30:00Z'},
    @{path='generator.initialized';value=$false},@{path='generator.drained';value=$false},@{path='generator.cancelled';value=$true},@{path='generator.warmupVerified';value=$false},@{path='generator.activeAtReturn';value=1},@{path='generator.workersRemainingAtReturn';value=1},
    @{path='generator.executionKind';value='simulated'},@{path='generator.credentialMode';value='implicit-token'},@{path='generator.credentialIsolation';value='unknown'},@{path='generator.workerCount';value=64},@{path='generator.sessionCleanupFailures';value=1},@{path='generator.sessionSetupFailures';value=1},
    @{path='before.queued';value=101},@{path='after.queued';value=36099},@{path='after.gaps';value=1},@{path='after.state';value='backpressure'},@{path='after.channel';value='Security'},
    @{path='queue.queued';value=34000},@{path='queue.retrying';value=-1},@{path='queue.deadLettered';value=1}
)
foreach($change in $changes){
    $f=Get-Fixture;$parts=$change.path.Split('.');$target=$f
    for($i=0;$i -lt $parts.Count-1;$i++){$target=$target.($parts[$i])}
    $target.($parts[-1])=$change.value
    if((Invoke-Readiness $f).readyForManualRestore){throw ('accepted: '+$change.path)};$checks++
}
$f=Get-Fixture;$f.generator.startedAt='2026-11-01T03:45:00Z';$f.generator.endedAt='2026-11-01T04:45:00Z';if((Invoke-Readiness $f).readyForManualRestore){throw 'generation began before fault'};$checks++
$f=Get-Fixture;$f.generator.resultCodes=[pscustomobject]@{'1727'=36000};if((Invoke-Readiness $f).readyForManualRestore){throw 'RPC failure'};$checks++
$f=Get-Fixture;$f.generator.sessionCleanupCodes=[pscustomobject]@{'2250'=3};if((Invoke-Readiness $f).readyForManualRestore){throw 'missing cleanup'};$checks++
$f=Get-Fixture;$f.generator.initializationFailureReasons=[pscustomobject]@{'worker-start'=1};if((Invoke-Readiness $f).readyForManualRestore){throw 'initialization failure'};$checks++
$f=Get-Fixture;$f.generator.seconds='SECRET-invalid-number';$result=Invoke-Readiness $f
if($result.readyForManualRestore -or ($result|ConvertTo-Json -Depth 5) -match 'SECRET'){throw 'unsafe malformed evidence'};$checks++
Write-Output "WEC outage observer: $checks checks passed (metadata-only fixtures)."
