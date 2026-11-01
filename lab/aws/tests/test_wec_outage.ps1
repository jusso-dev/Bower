# Windows fault restoration logic only. All firewall/clock calls are mocked.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path $PSScriptRoot '../monitoring/wec-destination-outage.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'parse' }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) { . ([scriptblock]::Create($function.Extent.Text)) }
function Get-WecOutageClock { return @{ utc = '2026-11-01T04:45:00Z'; ticks = $script:ticks; frequency = 1000; boot = $script:boot } }
function Get-NetFirewallRule { [CmdletBinding()]param($Name); if ($script:present) { return [pscustomobject]@{ Name=$Name; Direction='Outbound'; Action='Block'; Enabled=$script:enabled } } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule); process { [pscustomobject]@{ Program=$script:program } } }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule); process { [pscustomobject]@{ Protocol='TCP'; RemotePort='443' } } }
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule); process { if($script:removeFailure){throw 'SECRET-failure'};$script:present=$false;$script:removals++ } }
$root = Join-Path ([IO.Path]::GetTempPath()) ('bower-outage-' + [guid]::NewGuid().ToString('N'))
[void](New-Item $root -ItemType Directory)
$checks = 0
try {
    foreach ($case in @('good','early','reboot','missing-evidence','foreign-rule','remove-failure','disabled-rule','foreign-evidence')) {
        $script:present=$true;$script:enabled='True';$script:program='C:\Program Files\Bower\Bower.Collector.exe'
        $script:ticks=3600000;$script:boot='boot-one';$script:removals=0;$script:removeFailure=$false
        $run='bower-ws6-20261101-011000';$name='BowerOutage-'+$run
        $applied=@{runId=$run;name=$name;clock=@{ticks=0;frequency=1000;boot='boot-one'}}
        switch ($case) {
            'early' { $script:ticks=3599000 }
            'reboot' { $script:boot='boot-two' }
            'foreign-rule' { $script:program='C:\other.exe' }
            'remove-failure' { $script:removeFailure=$true }
            'disabled-rule' { $script:enabled='False' }
            'foreign-evidence' { $applied.runId='bower-ws6-20261101-999999' }
        }
        $applied | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root 'outage-applied.json')
        if($case -eq 'missing-evidence'){Remove-Item (Join-Path $root 'outage-applied.json')}
        $result=Invoke-WecOutageRestore $root $name $run 'off'
        $shouldRemove=$case -notin @('foreign-rule','remove-failure','disabled-rule')
        if($result.removed -ne $shouldRemove -or $script:removals -ne [int]$shouldRemove){throw "removal: $case"};$checks++
        if($result.minimumDurationPassed -ne ($case -eq 'good')){throw "duration: $case"};$checks++
        if(($result|ConvertTo-Json -Depth 5) -match 'SECRET' -or $result.deliveryQualified){throw "unsafe evidence: $case"};$checks++
        $stored=Get-Content (Join-Path $root 'outage-restored.json') -Raw | ConvertFrom-Json
        if($stored.removed -ne $result.removed -or $stored.minimumDurationPassed -ne $result.minimumDurationPassed){throw "stored result: $case"};$checks++
    }
    Write-Output "WEC outage restoration: $checks checks passed (firewall and clocks mocked)."
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
