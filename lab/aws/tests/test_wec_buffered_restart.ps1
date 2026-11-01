# Pure snapshot/ownership/restoration tests. No service, firewall, SQLite or cloud calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../monitoring/wec-buffered-restart.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse'}
foreach($function in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($function.Extent.Text))}
$checks=0
function Assert-Restart($Value,[string]$Label){if(-not $Value){throw $Label};$script:checks++}
$before=@{runId='bower-ws6-20261101-011000';phase='restart-01';planSha256=('a'*64);bootId='boot';executableSha256=('b'*64);sqliteSha256=('c'*64);environmentSha256=('d'*64);sourceConfigSha256=('e'*64);allWinevtIdsSha256=('f'*64);phaseIdsSha256=('a'*64);bookmarkRecordId=50000;allWinevtCount=50000;phaseCount=600;delivered=49000;pending=700;deadLettered=0;sourceHealthy=$true;serviceAccount='NT SERVICE\Bower';processId=42;processStartedTicks=10}
$after=$before.Clone();$after.processId=43;$after.processStartedTicks=20;$after.pending=701;$after.faultActiveBeforeSnapshot=$true;$after.faultActiveAfterSnapshot=$true
$result=Compare-WecRestartSnapshot $before $after
Assert-Restart ($result.acceptedQueueRecoveryVerified -and -not $result.deliveryQualified -and -not $result.destinationQueryVerified) 'valid isolated recovery'
foreach($field in @('runId','phase','planSha256','bootId','executableSha256','sqliteSha256','environmentSha256','sourceConfigSha256','allWinevtIdsSha256','phaseIdsSha256','bookmarkRecordId','allWinevtCount','phaseCount','delivered')){
    $bad=$after.Clone();$bad[$field]='changed'
    Assert-Restart (-not (Compare-WecRestartSnapshot $before $bad).acceptedQueueRecoveryVerified) ('changed '+$field)
}
foreach($change in @(@{field='faultActiveBeforeSnapshot';value=$false},@{field='faultActiveAfterSnapshot';value=$false},@{field='pending';value=599},@{field='pending';value=699},@{field='deadLettered';value=1},@{field='sourceHealthy';value=$false},@{field='serviceAccount';value='LocalSystem'},@{field='processId';value=42},@{field='processId';value=0},@{field='processStartedTicks';value=10})){
    $bad=$after.Clone();$bad[$change.field]=$change.value
    Assert-Restart (-not (Compare-WecRestartSnapshot $before $bad).acceptedQueueRecoveryVerified) ('unsafe '+$change.field)
}
$empty=$before.Clone();$empty.bookmarkRecordId=0;$emptyAfter=$after.Clone();$emptyAfter.bookmarkRecordId=0
Assert-Restart (-not (Compare-WecRestartSnapshot $empty $emptyAfter).acceptedQueueRecoveryVerified) 'absent bookmark'
Assert-Restart ((ConvertTo-WecRestartTimestamp ([datetime]::SpecifyKind([datetime]'2026-11-01T03:00:00',[DateTimeKind]::Utc))).Offset.TotalSeconds -eq 0) 'typed UTC timestamp'
$badTimestamp=$false;try{ConvertTo-WecRestartTimestamp ([datetime]::SpecifyKind([datetime]'2026-11-01',[DateTimeKind]::Unspecified))|Out-Null}catch{$badTimestamp=$true}
Assert-Restart $badTimestamp 'unspecified timestamp'
$script:application='C:\Program Files\Bower\Bower.Collector.exe';$script:port='443';$script:protocol='TCP';$script:present=$true;$script:enabled='True';$script:removed=0
function Get-NetFirewallApplicationFilter{[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process{if($null -eq $InputObject){throw 'mock-rule-missing'};[pscustomobject]@{Program=$script:application}}}
function Get-NetFirewallPortFilter{[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process{if($null -eq $InputObject){throw 'mock-rule-missing'};[pscustomobject]@{RemotePort=$script:port;Protocol=$script:protocol}}}
function Get-NetFirewallRule{[CmdletBinding()]param([string]$Name) if($Name -cne 'owned'){throw 'mock-rule-name'};if($script:present){[pscustomobject]@{Direction='Outbound';Action='Block';Enabled=$script:enabled}}}
function Remove-NetFirewallRule{[CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject) process{if($null -eq $InputObject){throw 'mock-rule-missing'};if($PSCmdlet.ShouldProcess('fake rule','remove')){$script:removed++;$script:present=$false}}}
Assert-Restart (Get-WecRestartFaultState 'owned').active 'owned active fault'
$script:present=$false;Assert-Restart (-not (Get-WecRestartFaultState 'owned').active) 'guard removed rule'
$script:present=$true;$script:enabled='False';Assert-Restart (-not (Get-WecRestartFaultState 'owned').active) 'disabled recovery rule'
$script:enabled='True';$script:application='foreign';Assert-Restart (-not (Get-WecRestartFaultState 'owned').active) 'foreign recovery rule'
$script:application='C:\Program Files\Bower\Bower.Collector.exe'
$directory=Join-Path ([IO.Path]::GetTempPath()) ('bower-restart-fixture-'+[guid]::NewGuid().ToString('N'))
[void](New-Item $directory -ItemType Directory)
try {
    $result=Restore-WecRestartFault $directory 'owned' 'run' 'test'
    Assert-Restart ($result.removed -and $script:removed -eq 1) 'owned restoration'
    $result=Restore-WecRestartFault $directory 'owned' 'run' 'test-again'
    Assert-Restart ($result.removed -and $script:removed -eq 1 -and @(Get-ChildItem $directory -Filter 'restore-*.json').Count -eq 2) 'repeat restoration keeps evidence'
    foreach($bad in @('application','port','protocol')){
        $script:present=$true;Set-Variable -Name $bad -Scope Script -Value 'foreign'
        $result=Restore-WecRestartFault $directory 'owned' 'run' 'test'
        Assert-Restart (-not $result.removed -and $script:present -and $script:removed -eq 1) ('foreign '+$bad)
        $script:application='C:\Program Files\Bower\Bower.Collector.exe';$script:port='443';$script:protocol='TCP'
    }
    $path=Join-Path $directory 'immutable.json';Write-WecRestartJson $path @{value=1}
    $failed=$false;try{Write-WecRestartJson $path @{value=2}}catch{$failed=$true}
    Assert-Restart ($failed -and (Get-Content $path -Raw|ConvertFrom-Json).value -eq 1) 'evidence overwrite'
    # Even an evidence-write failure must occur after connectivity restoration.
    $script:present=$true;$missing=Join-Path $directory 'missing'
    $failed=$false;try{Restore-WecRestartFault $missing 'owned' 'run' 'disk-failure'|Out-Null}catch{$failed=$true}
    Assert-Restart ($failed -and -not $script:present -and $script:removed -eq 2) 'restore precedes evidence write'
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
Write-Output "WEC buffered restart: $checks checks passed (all host actions mocked)."
