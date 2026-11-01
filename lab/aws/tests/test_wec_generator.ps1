# Local scheduler/cleanup/checkpoint tests only. The injected backend never invokes Windows or SMB.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path $PSScriptRoot '../monitoring/wec-qualification.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'generator parse' }
$functions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }
$generator = $functions | Where-Object { $_.Name -eq 'Add-WecGenerator' }
$source = $generator.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString }, $true)[0].Value
$fake = @'
public sealed class BowerWecFakeNative : IBowerWecNetworkNative {
    public string Mode="normal";
    public int Created,Impersonated,Connected,Cancelled,Reverted,Closed,ActiveConnections,ActiveCleanup;
    public bool RequireSerialCleanup=false;
public int CleanupDelayMilliseconds=1;
public long FirstCleanupStartedTicks,LastCleanupFinishedTicks,LastConnectFinishedTicks;
    public bool Stable=true,ExplicitOnly=true,UnexpectedToken=false;
    public bool OwnershipFailure=false;
    public readonly System.Collections.Concurrent.ConcurrentDictionary<int,int> SessionCalls=new System.Collections.Concurrent.ConcurrentDictionary<int,int>();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int,bool> closedTokens=new System.Collections.Concurrent.ConcurrentDictionary<int,bool>();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int,bool> cancelledTokens=new System.Collections.Concurrent.ConcurrentDictionary<int,bool>();
    private readonly System.Threading.ThreadLocal<int> currentToken=new System.Threading.ThreadLocal<int>();
    private string firstPassword;
    private readonly object gate=new object();
    public IntPtr CreateToken(string account,string password) {
        int id=System.Threading.Interlocked.Increment(ref Created);
        lock(gate){if(firstPassword==null)firstPassword=password;else if(firstPassword!=password)Stable=false;}
        if(Mode=="initialization-blocked")System.Threading.Thread.Sleep(400);
        if(Mode=="setup-failure")throw new System.ComponentModel.Win32Exception(5);
        return new IntPtr(id);
    }
    public void Impersonate(IntPtr token) {
        System.Threading.Interlocked.Increment(ref Impersonated);
        if(token.ToInt32()<1 || token.ToInt32()>Created)UnexpectedToken=true;
        currentToken.Value=token.ToInt32();
        if(Mode=="impersonation-failure")throw new System.ComponentModel.Win32Exception(5);
    }
    public int Connect(string account,string password,bool explicitCredentials) {
        System.Threading.Interlocked.Increment(ref Connected);
        if(currentToken.Value<1)OwnershipFailure=true;
        SessionCalls.AddOrUpdate(currentToken.Value,1,delegate(int k,int v){return v+1;});
        if(Mode=="concurrent"){System.Threading.Interlocked.Increment(ref ActiveConnections);System.Threading.Thread.Sleep(25);System.Threading.Interlocked.Decrement(ref ActiveConnections);}
        lock(gate){if(firstPassword!=password)Stable=false;if(!explicitCredentials)ExplicitOnly=false;}
        if(Mode=="blocked")System.Threading.Thread.Sleep(400);
        if(Mode=="connect-exception")throw new InvalidOperationException("SECRET-not-for-evidence");
        System.Threading.Interlocked.Exchange(ref LastConnectFinishedTicks,DateTimeOffset.UtcNow.UtcDateTime.Ticks);
return Mode=="unexpected-success"?0:1326;
    }
    public int Cancel(){
System.Threading.Interlocked.CompareExchange(ref FirstCleanupStartedTicks,DateTimeOffset.UtcNow.UtcDateTime.Ticks,0);
if(RequireSerialCleanup){
if(ActiveConnections!=0 || System.Threading.Interlocked.Increment(ref ActiveCleanup)!=1)OwnershipFailure=true;
System.Threading.Thread.Sleep(CleanupDelayMilliseconds);
System.Threading.Interlocked.Decrement(ref ActiveCleanup);
}
if(currentToken.Value<1 || !cancelledTokens.TryAdd(currentToken.Value,true))OwnershipFailure=true;
System.Threading.Interlocked.Increment(ref Cancelled);
System.Threading.Interlocked.Exchange(ref LastCleanupFinishedTicks,DateTimeOffset.UtcNow.UtcDateTime.Ticks);
return Mode=="cleanup-failure"?5:2250;
}
    public bool Revert(){currentToken.Value=0;System.Threading.Interlocked.Increment(ref Reverted);return true;}
    public bool Close(IntPtr token){if(!closedTokens.TryAdd(token.ToInt32(),true))OwnershipFailure=true;System.Threading.Interlocked.Increment(ref Closed);return true;}
}
'@
Add-Type -TypeDefinition ($source + "`n" + $fake)
$checks = 0
function Assert-Generator($Condition, [string]$Message) { if (-not $Condition) { throw $Message }; $script:checks++ }
$directory = Join-Path ([IO.Path]::GetTempPath()) ('bower-generator-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
try {
    $cancel = Join-Path $directory 'cancel'
    $backend = New-Object BowerWecFakeNative
    $result = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 10, 1, $cancel, 'phase-explicit', $backend, 1000)
    Assert-Generator ($result.executionKind -ceq 'simulated') 'test backend not marked simulated'
    Assert-Generator ($result.requested -eq 10 -and $result.completed -eq 10 -and $result.resultCodes['1326'] -eq 10) 'work accounting'
    Assert-Generator ($result.drained -and $result.workersRemainingAtReturn -eq 0 -and $result.activeAtReturn -eq 0) 'work drained'
    Assert-Generator ($backend.Created -eq 1 -and $backend.Closed -eq 1 -and $backend.Cancelled -eq 1) 'owned single LUID cleanup'
    Assert-Generator ($backend.Stable -and $backend.ExplicitOnly -and -not $backend.UnexpectedToken) 'explicit stable credential isolation'
    Assert-Generator ($backend.Impersonated -eq $backend.Reverted) 'impersonated thread leaked'
    Assert-Generator ($result.workerCount -eq 10 -and $result.sessionCleanupCodes['2250'] -eq 1) 'worker/cleanup counters'
    Assert-Generator (($result | ConvertTo-Json -Depth 8) -notmatch 'synthetic-invalid|SECRET|password') 'credential leakage'
    $backend = New-Object BowerWecFakeNative
    $diagnostic = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 1, 1, $cancel, 'worker-null', $backend, 1000)
    Assert-Generator ($diagnostic.requested -eq 1 -and $diagnostic.workerCount -eq 1 -and $backend.Created -eq 1 -and -not $backend.ExplicitOnly) 'bounded legacy diagnostic'
    foreach ($mode in 'setup-failure','impersonation-failure','cleanup-failure','connect-exception','unexpected-success','blocked','initialization-blocked') {
        $backend = New-Object BowerWecFakeNative; $backend.Mode = $mode
        # Ordinary failure accounting must not race a 50ms thread-start deadline
        # on a busy CI host. Only the deliberate timeout cases use that deadline.
        $timeoutCase = $mode -in @('blocked', 'initialization-blocked')
        $waitMilliseconds = if ($timeoutCase) { 50 } else { 5000 }
        $result = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 1, 1, $cancel, 'phase-explicit', $backend, $waitMilliseconds)
        if (-not $timeoutCase) {
            Assert-Generator ($result.initialized -and $result.drained -and $result.workersRemainingAtReturn -eq 0) 'failure-accounting worker did not finish'
        }
        switch ($mode) {
            'setup-failure' { Assert-Generator ($result.sessionSetupFailures -eq 1 -and $result.scheduled -eq 0 -and $result.sessionResultCodes['5'] -eq 1) 'setup failure lost' }
            'impersonation-failure' { Assert-Generator ($result.impersonationFailures -eq 1 -and $result.scheduled -eq 0) 'impersonation failure lost' }
            'cleanup-failure' { Assert-Generator ($result.sessionCleanupFailures -eq 1 -and $result.sessionCleanupCodes['5'] -eq 1) 'cleanup failure lost' }
            'connect-exception' { Assert-Generator ($result.completed -eq 1 -and $result.resultCodes['-1'] -eq 1) 'connect failure accounting' }
            'unexpected-success' { Assert-Generator ($result.unexpectedSuccesses -eq 1 -and $backend.Cancelled -eq 1) 'unexpected success lost' }
            'initialization-blocked' { Assert-Generator (-not $result.initialized -and -not $result.drained -and $result.scheduled -eq 0 -and $result.initializationFailureReasons['ready-timeout'] -eq 1) 'initialization timeout lost' }
            'blocked' { Assert-Generator (-not $result.drained -and $result.activeAtReturn -eq 1 -and $result.completed -eq 0) 'blocked worker falsely drained' }
        }
        $checkpoint = Join-Path $directory ($mode + '.json')
        $output = Write-WecGeneratorCheckpoint $checkpoint 'bower-ws6-20261101-011000' $mode 'diagnostic' $result
        $saved = [IO.File]::ReadAllText($checkpoint) | ConvertFrom-Json
        Assert-Generator ($saved.generator.drained -eq $result.drained -and $saved.nativeVerified -eq $false) 'failed generator checkpoint lost'
        Assert-Generator ($output -notmatch 'SECRET|synthetic-invalid|password' -and $output -eq ([IO.File]::ReadAllText($checkpoint).Trim())) 'checkpoint privacy/output mismatch'
        if ($mode -in @('blocked','initialization-blocked')) { Start-Sleep -Milliseconds 500; Assert-Generator ($backend.Cancelled -eq 1 -and $backend.Closed -eq 1) 'late worker owned cleanup lost' }
    }
    [IO.File]::WriteAllText($cancel, 'cancel')
    $backend = New-Object BowerWecFakeNative
    $cancelled = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 1, 1, $cancel, 'phase-explicit', $backend, 1000)
    Assert-Generator ($cancelled.cancelled -and $cancelled.scheduled -eq 0 -and $backend.Connected -eq 0 -and $backend.Cancelled -eq 1 -and $backend.Closed -eq 1) 'cancelled owned session cleanup'
    Remove-Item -LiteralPath $cancel
    $backend = New-Object BowerWecFakeNative
    $script:warmupCallbackCount = 0
    $script:warmupCompletedAt = $null
    $callback = [Action[object]] { param($metadata)
        if ($metadata.requested -ne 100 -or $metadata.requestedRate -ne 10 -or $metadata.completed -ne 100 -or -not $metadata.drained) { throw 'warmup-accounting' }
        $script:warmupCallbackCount++
        $script:warmupCompletedAt = [DateTimeOffset]::UtcNow
    }
    $warmupWallClock = [Diagnostics.Stopwatch]::StartNew()
    $warmed = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 10, 1, $cancel, 'phase-explicit', $backend, 1000, $true, $callback)
    Assert-Generator ($warmed.warmupVerified -and $warmed.warmupRequired -and $script:warmupCallbackCount -eq 1) 'warmup callback missing'
    Assert-Generator ($warmed.completed -eq 10 -and $warmed.resultCodes['1326'] -eq 10 -and $backend.Connected -eq 110) 'warmup included in measured count'
    $warmupWallClock.Stop()
    $observedWarmupSeconds = ([DateTimeOffset]::Parse($warmed.warmup.endedAt) - [DateTimeOffset]::Parse($warmed.warmup.startedAt)).TotalSeconds
    # A fake backend proves interval boundaries, not the native throughput gate.
    # Compare independently observed total wall time against the full warm-up;
    # slow Windows scheduling may extend the measured phase without failing it.
    Assert-Generator ($warmupWallClock.Elapsed.TotalSeconds - $warmed.seconds -ge $observedWarmupSeconds - 0.25) 'warmup included in measured interval'
    Assert-Generator ([DateTimeOffset]::Parse($warmed.startedAt) -ge $script:warmupCompletedAt) 'measured clock started before warmup drain'
    Assert-Generator ($backend.Created -eq 1 -and $backend.Closed -eq 1 -and $backend.Cancelled -eq 1 -and $backend.Stable) 'warmup changed owned credential session'
    $backend = New-Object BowerWecFakeNative
    $failedWarmup = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 1, 1, $cancel, 'phase-explicit', $backend, 1000, $true,
        [Action[object]] { param($metadata) throw 'SECRET-warmup-not-drained' })
    Assert-Generator (-not $failedWarmup.warmupVerified -and $failedWarmup.scheduled -eq 0 -and $failedWarmup.completed -eq 0) 'failed warmup allowed measured traffic'
    Assert-Generator (($failedWarmup | ConvertTo-Json -Depth 8) -notmatch 'SECRET' -and $backend.Closed -eq 1) 'warmup failure leaked or missed cleanup'
    $backend = New-Object BowerWecFakeNative; $backend.Mode = 'concurrent'; $backend.RequireSerialCleanup = $true; $backend.CleanupDelayMilliseconds = 100
    $script:workerWarmupSessions = 0
    $workerCallback = [Action[object]] { param($metadata)
        $script:workerWarmupSessions = $backend.SessionCalls.Count
        if ($metadata.completed -ne 100 -or $script:workerWarmupSessions -ne 4) { throw 'worker-warmup' }
    }
    $isolated = [BowerWecNetworkGenerator]::RunWithNative('bwraaaaaaaaaaaaaaaaa', 100, 1, $cancel, 'worker-explicit', $backend, 1000, $true, $workerCallback)
    Assert-Generator ($isolated.warmupVerified -and $script:workerWarmupSessions -eq 4) 'every owned session must warm up'
    Assert-Generator ($isolated.completed -eq 100 -and $isolated.resultCodes['1326'] -eq 100 -and $backend.Connected -eq 200) 'worker measured accounting'
    $measuredEndTicks = [DateTimeOffset]::Parse($isolated.endedAt).UtcDateTime.Ticks
    # Four deliberately slow, serialized cleanup calls run after native work.
    # Timestamp ordering tests their exclusion without a tight one-second SLA.
    # .NET Framework AddSeconds rounds to milliseconds, hence the 2 ms bound.
    $roundingTicks = 2 * [TimeSpan]::TicksPerMillisecond
    Assert-Generator ($measuredEndTicks -ge $backend.LastConnectFinishedTicks - $roundingTicks -and
        $measuredEndTicks -le $backend.FirstCleanupStartedTicks + $roundingTicks) 'measured end must bound completed native work before cleanup'
    Assert-Generator ($backend.LastCleanupFinishedTicks - $measuredEndTicks -ge 100 * [TimeSpan]::TicksPerMillisecond) 'serialized cleanup included in generation interval'
    Assert-Generator ($isolated.maxConcurrency -ge 2 -and $isolated.drained -and $isolated.workersRemainingAtReturn -eq 0) 'isolated concurrent work/drain'
    Assert-Generator ($backend.Created -eq 4 -and $backend.Cancelled -eq 4 -and $backend.Closed -eq 4 -and $isolated.sessionCleanupCodes['2250'] -eq 4) 'all owned worker sessions cleaned'
    Assert-Generator ($backend.Stable -and $backend.ExplicitOnly -and -not $backend.OwnershipFailure -and -not $backend.UnexpectedToken) 'worker credential and handle ownership'
    Assert-Generator ($isolated.credentialIsolation -eq 'per-worker-logon-new-credentials' -and $isolated.credentialMode -eq 'explicit-stable-per-phase') 'worker profile metadata'
    # Persist BEFORE any timestamp conversion: malformed timing cannot erase numeric diagnostics.
    $result.startedAt = 'invalid-time'
    $timingPath = Join-Path $directory 'bad-time.json'
    Write-WecGeneratorCheckpoint $timingPath 'bower-ws6-20261101-011000' 'bad-time' 'diagnostic' $result | Out-Null
    try { [DateTimeOffset]::Parse($result.startedAt) | Out-Null } catch { }
    Assert-Generator ((Test-Path $timingPath) -and (Get-Content $timingPath -Raw | ConvertFrom-Json).generator.startedAt -eq 'invalid-time') 'timing failure erased summary'
    $overwritten = $false
    try { Write-WecGeneratorCheckpoint $timingPath 'run' 'phase' 'diagnostic' $result | Out-Null; $overwritten = $true } catch { }
    Assert-Generator (-not $overwritten) 'existing failure checkpoint overwritten'
    $oversized = $false
    try { Write-WecGeneratorCheckpoint (Join-Path $directory 'huge.json') 'run' 'phase' 'diagnostic' @{ data = ('x' * 32768) } | Out-Null; $oversized = $true } catch { }
    Assert-Generator (-not $oversized -and -not (Test-Path (Join-Path $directory 'huge.json'))) 'unbounded checkpoint accepted'
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
Write-Output "WEC generator validation: $checks checks passed (injected fake native backend; no Windows/SMB/cloud calls)."
