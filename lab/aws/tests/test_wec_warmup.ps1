# Warm-up reconciliation tests; native channels, source status and SQLite are mocked.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '../monitoring/wec-qualification.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'warmup parse'}
foreach($function in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($function.Extent.Text))}
Add-Type -TypeDefinition @'
public static class BowerWecQueueMetadata {
    public static string[][] Rows;
    public static string[][] Read(string path) {return Rows;}
}
'@
function Add-WecQueueReader { }
$script:ids=@(('winevt-'+('a'*32)),('winevt-'+('b'*32)))
function Get-WecEventIdentity { return @{count=2;unique=2;invalidNetworkLogons=0;ids=$script:ids} }
function Get-WecStatus { return $script:sourceAfter }
$checks=0
function Assert-Warmup($Condition,[string]$Label){if(-not $Condition){throw $Label};$script:checks++}
$directory=Join-Path ([IO.Path]::GetTempPath()) ('bower-warmup-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory|Out-Null
try {
    foreach($case in 'complete','queue-extra','source-error','expired') {
        $now=[DateTimeOffset]::UtcNow
        $metadata=@{requested=100;requestedRate=10;scheduled=100;completed=100;drained=$true;
            startedAt=$now.AddSeconds(-15).ToString('o');endedAt=$now.AddSeconds(-6).ToString('o');
            deadlineAt=$now.AddSeconds(15).ToString('o')}
        if($case -eq 'expired'){$metadata.deadlineAt=$now.AddSeconds(-1).ToString('o')}
        $before=@{queued=0;state='running'}
        foreach($key in 'rejected','parserErrors','malformed','oversized','gaps','resets','cursorConflicts'){$before[$key]=0}
        $script:sourceAfter=$before.Clone();$script:sourceAfter.queued=2
        if($case -eq 'source-error'){$script:sourceAfter.parserErrors=1}
        $queueIds=$script:ids
        if($case -eq 'queue-extra'){$queueIds+=('winevt-'+('c'*32))}
        [BowerWecQueueMetadata]::Rows=[string[][]]@($queueIds|ForEach-Object {,@($_,$now.AddSeconds(-10).ToString('o'))})
        $failed=$false;$baseline=$null
        try {$baseline=Complete-WecWarmup $directory $case 'bwraaaaaaaaaaaaaaaaa' $before $metadata}catch{$failed=$true}
        Assert-Warmup ($failed -eq ($case -ne 'complete')) "unexpected warmup outcome $case"
        $saved=Get-Content (Join-Path $directory "$case-warmup.json") -Raw|ConvertFrom-Json
        Assert-Warmup ($saved.warmupVerified -eq ($case -eq 'complete') -and -not $saved.measuredQualification -and -not $saved.deliveryQualified) "incorrect evidence claim $case"
        if($case -eq 'complete') {
            Assert-Warmup ($baseline.queued -eq 2 -and $metadata.nativeCount -eq 2 -and $metadata.queueCount -eq 2) 'baseline not after warmup'
            Assert-Warmup ($metadata.nativeIdsSha256 -ceq $metadata.forwardedIdsSha256 -and $metadata.nativeIdsSha256 -ceq $metadata.queueIdsSha256) 'warmup identity hashes differ'
            Assert-Warmup (@(Get-ChildItem $directory -Filter 'complete-warmup-*.ids').Count -eq 3) 'exact warmup IDs missing'
        } else {
            Assert-Warmup ($null -eq $baseline -and $null -ne $saved.failure) 'failed warmup supplied measured baseline'
        }
    }
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
Write-Output "WEC warmup validation: $checks checks passed (all native readers mocked)."
