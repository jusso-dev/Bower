# Local-only tests: never invoke Windows host actions or native SQLite functions.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path $PSScriptRoot '../monitoring'
foreach ($name in 'wec-qualification.ps1', 'wec-destination-outage.ps1') {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $name), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'script parse failed' }
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
}
Add-WecQueueReader # Compiles P/Invoke declarations, never calls winsqlite3 on this host.
$tests = 1
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'invalid metadata accepted' }
    $script:tests++
}
try { throw 'synthetic-password-never-output CS0121' } catch { $safe = Get-WecQualificationFailure $_ }
$serialized = $safe | ConvertTo-Json -Compress
if ($serialized -match 'synthetic-password' -or $safe.staticCode -cne 'unclassified' -or $safe.compilerCodes -cnotcontains 'CS0121' -or $safe.scriptLine -lt 1) { throw 'unsafe qualification diagnostic' }; $tests++
try { throw 'generator-workers-timed-out' } catch { $safe = Get-WecQualificationFailure $_ }
if ($safe.staticCode -cne 'generator-workers-timed-out' -or $safe.compilerCodes.Count -ne 0) { throw 'static qualification diagnostic' }; $tests++
$a = 'winevt-' + ('a' * 32)
$b = 'winevt-' + ('b' * 32)
$c = 'winevt-' + ('c' * 32)
$since = [DateTimeOffset]'2026-11-01T01:00:00Z'
$until = $since.AddMinutes(1)
$inside = $since.AddSeconds(2).ToString('o')
$old = $since.AddMinutes(-1).ToString('o')
$rows = @(@($a, $inside), @($b, $inside), @($c, $old))
$ids = Select-WecQueueIdentity $rows @($a, $b) $since $until
if ($ids.Count -ne 2 -or ($ids -join ',') -cne "$a,$b") { throw 'exact queue identities' }; $tests++
$ids = Select-WecQueueIdentity @(@($a, $inside), @($c, $inside)) @($a) $since $until
if ($ids.Count -ne 2 -or $ids -cnotcontains $c) { throw 'extra identity omitted' }; $tests++
Assert-Rejected { Select-WecQueueIdentity @(@($a, $old)) @($a) $since $until }
Assert-Rejected { Select-WecQueueIdentity @(@($a, $inside), @($a, $inside)) @($a) $since $until }
Assert-Rejected { Select-WecQueueIdentity @(@('unsafe raw value', $inside)) @($a) $since $until }
Assert-Rejected { Select-WecQueueIdentity $rows @($a, $a) $since $until }

# The event window explicitly covers a late audit timestamp without changing
# the generator interval, and rate proof comes from actual native event times.
$attemptEnd = [DateTimeOffset]'2026-11-01T01:00:10Z'
$eventEnd = Get-WecEventWindowEnd $attemptEnd
if (($eventEnd - $attemptEnd).TotalSeconds -ne 5) { throw 'unbounded audit window' }; $tests++
$lateAudit = $attemptEnd.AddMilliseconds(20)
if (-not ($lateAudit -gt $attemptEnd -and $lateAudit -lt $eventEnd)) { throw 'late audit omitted' }; $tests++
if ((Get-WecObservedRate 1000 '2026-11-01T01:00:00Z' '2026-11-01T01:00:09.99Z') -lt 99.99) { throw 'observed rate wrong' }; $tests++
if ((Get-WecObservedRate 1000 '2026-11-01T01:00:00Z' '2026-11-01T01:00:12Z') -ge 99) { throw 'slow native events passed rate' }; $tests++
if ((Get-WecObservedRate 1000 '2026-11-01T01:00:00Z' '2026-11-01T01:00:00Z') -ne 0) { throw 'zero event interval' }; $tests++
if ((Get-WecObservedRate 0 '' '') -ne 0) { throw 'empty event rate' }; $tests++

# Preserve and parse the exact generated restoration function bundle, then mock
# OS operations to exercise deletion ownership, duration and failed evidence.
$bundle = "function Get-WecOutageClock {`n${function:Get-WecOutageClock}`n}`n" +
    "function Assert-WecOutageRule {`n${function:Assert-WecOutageRule}`n}`n" +
    "function Invoke-WecOutageRestore {`n${function:Invoke-WecOutageRestore}`n}`n"
$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseInput($bundle, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { throw 'restoration bundle parse' }; $tests++
. ([scriptblock]::Create($bundle))
function Get-WecOutageClock { return @{ utc = '2026-11-01T02:10:00Z'; ticks = 4000000; frequency = 1000; boot = 'boot1' } }
function Get-NetFirewallRule { if ($script:present) { return [pscustomobject]@{ Direction = 'Outbound'; Action = 'Block'; Enabled = 'True' } } }
function Get-NetFirewallApplicationFilter { return [pscustomobject]@{ Program = $script:program } }
function Get-NetFirewallPortFilter { return [pscustomobject]@{ Protocol = 'TCP'; RemotePort = '443' } }
function Remove-NetFirewallRule { $script:present = $false; $script:removed++ }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('bower-wec-evidence-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp | Out-Null
try {
    foreach ($case in 'complete', 'foreign', 'early', 'reboot', 'missing-applied') {
        $script:present = $true; $script:removed = 0
        $script:program = if ($case -eq 'foreign') { 'C:\foreign.exe' } else { 'C:\Program Files\Bower\Bower.Collector.exe' }
        $ticks = if ($case -eq 'early') { 3900000 } else { 0 }
        $boot = if ($case -eq 'reboot') { 'other-boot' } else { 'boot1' }
        @{ runId = 'run'; name = 'rule'; clock = @{ ticks = $ticks; frequency = 1000; boot = $boot } } |
            ConvertTo-Json -Depth 4 | Set-Content (Join-Path $temp 'outage-applied.json')
        if ($case -eq 'missing-applied') { Remove-Item (Join-Path $temp 'outage-applied.json') }
        $result = Invoke-WecOutageRestore $temp 'rule' 'run' 'automatic-off'
        if ($case -eq 'foreign') {
            if ($result.removed -or $script:removed -ne 0) { throw 'foreign rule removed' }
        } else {
            if (-not $result.removed -or $script:removed -ne 1) { throw "owned rule not removed: $case" }
        }
        if ($result.minimumDurationPassed -ne ($case -eq 'complete')) { throw "incorrect qualification: $case" }
        if (-not (Test-Path (Join-Path $temp 'outage-restored.json'))) { throw 'missing independent restoration evidence' }
        $tests++
    }
} finally { Remove-Item $temp -Recurse -Force }
Write-Output "WEC evidence validation: $tests checks passed (OS calls mocked; no host actions)."
