# Exercises the child pipe protocol with a simulated native implementation.
# No Windows logon, SMB, cloud, or real credentials are used.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../monitoring/wec-qualification.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'parse' }
$function = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-WecProcessScript' }, $false)[0]
. ([scriptblock]::Create($function.Extent.Text))
$directory = Join-Path ([IO.Path]::GetTempPath()) ('bower-worker-' + [guid]::NewGuid().ToString('N'))
[void](New-Item $directory -ItemType Directory)
$checks = 0
function Assert-Process($Condition, [string]$Name) { if (-not $Condition) { throw $Name }; $script:checks++ }
$native = @'
using System;
public sealed class BowerWecWindowsNative {
    public IntPtr CreateToken(string account,string password){return new IntPtr(1);}
    public void Impersonate(IntPtr token){}
    public int Connect(string account,string password,bool explicitCredentials){return 1326;}
    public int Cancel(){return 2250;}
    public bool Revert(){return true;}
    public bool Close(IntPtr token){return true;}
}
'@
function Invoke-FakeWorker([string]$Path, [string[]]$Lines) {
    $process = New-Object Diagnostics.Process
    $process.StartInfo = New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = (Get-Process -Id $PID).Path
    $process.StartInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $Path + '"'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.CreateNoWindow = $true
    try {
        [void]$process.Start()
        foreach ($line in $Lines) { $process.StandardInput.WriteLine($line) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(20000)) { throw 'worker-timeout' }
        return @{ code = $process.ExitCode; output = $process.StandardOutput.ReadToEnd(); errorOutput = $process.StandardError.ReadToEnd() }
    } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
}
try {
    $path = Write-WecProcessScript $directory 'protocol' $native
    $childTokens = $null; $childErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$childTokens, [ref]$childErrors)
    Assert-Process ($childErrors.Count -eq 0) 'child script syntax'
    $inputLine = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("bwraaaaaaaaaaaaaaaaa`nsynthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    $result = Invoke-FakeWorker $path @($inputLine, 'connect', 'cancel', 'revert', 'close')
    Assert-Process ($result.code -eq 0) 'child clean exit'
    Assert-Process (($result.output -split '\r?\n' | Where-Object { $_ }) -join ',' -eq '0,1326,2250,0,0') 'child fixed numeric protocol'
    Assert-Process ($result.errorOutput -eq '') 'child stderr'
    $result = Invoke-FakeWorker $path @($inputLine, 'SECRET-invalid-command')
    Assert-Process ($result.code -ne 0 -and $result.output -notmatch 'SECRET' -and $result.errorOutput -notmatch 'SECRET') 'invalid command leakage'
    $result = Invoke-FakeWorker $path @('invalid-base64-SECRET')
    Assert-Process ($result.code -ne 0 -and $result.output.Trim() -eq '-1' -and $result.errorOutput -eq '') 'invalid input leakage'
    $result = Invoke-FakeWorker $path @($inputLine)
    Assert-Process ($result.code -ne 0) 'EOF cannot report cleanup success'
    $errorNative = $native.Replace('return 1326;', 'throw new System.ComponentModel.Win32Exception(5,"SECRET-native-error");')
    $errorPath = Write-WecProcessScript $directory 'native-error' $errorNative
    $result = Invoke-FakeWorker $errorPath @($inputLine, 'connect')
    Assert-Process ($result.code -ne 0 -and $result.output -match '5' -and $result.output -notmatch 'SECRET' -and $result.errorOutput -eq '') 'native error metadata only'
        $generatorFunction = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-WecGenerator' }, $false)[0]
        $source = $generatorFunction.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString }, $true)[0].Value
    $fixture = @'
public static class BowerProcessTransportChecks {
    private static bool Alive(int id) {try {using(var p=System.Diagnostics.Process.GetProcessById(id))return !p.HasExited;}catch(System.ArgumentException){return false;}}
    public static bool Fault(string path,string executable) {
        int pid=0;bool failed=false;double elapsed=0;
        var backend=new BowerWecProcessNative(path,delegate(System.Diagnostics.ProcessStartInfo info){
            info.FileName=executable;var p=new System.Diagnostics.Process {StartInfo=info};p.Start();pid=p.Id;return p;
        },1000);
        try {
            var token=backend.CreateToken("bwraaaaaaaaaaaaaaaaa","synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");backend.Impersonate(token);
            var watch=System.Diagnostics.Stopwatch.StartNew();
            try {backend.Connect("bwraaaaaaaaaaaaaaaaa","synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",true);}catch{failed=true;}
            elapsed=watch.Elapsed.TotalSeconds;
        } finally {backend.Dispose();}
        return failed && elapsed<4 && !Alive(pid) && !backend.NativeExecution;
    }
    public static bool LateRegistration(string path,string executable) {
        var entered=new System.Threading.ManualResetEventSlim(false);var release=new System.Threading.ManualResetEventSlim(false);
        var disposeReturned=new System.Threading.ManualResetEventSlim(false);int pid=0,starts=0;bool rejected=false;
        var backend=new BowerWecProcessNative(path,delegate(System.Diagnostics.ProcessStartInfo info){
            System.Threading.Interlocked.Increment(ref starts);entered.Set();if(!release.Wait(5000))throw new System.TimeoutException();
            info.FileName=executable;var p=new System.Diagnostics.Process {StartInfo=info};p.Start();pid=p.Id;return p;
        },1000);
        var create=new System.Threading.Thread(delegate(){try{backend.CreateToken("bwraaaaaaaaaaaaaaaaa","synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");}catch{}});
        var dispose=new System.Threading.Thread(delegate(){backend.Dispose();disposeReturned.Set();});
        create.IsBackground=true;dispose.IsBackground=true;
        try {
            create.Start();if(!entered.Wait(5000))return false;dispose.Start();System.Threading.Thread.Sleep(50);
            if(disposeReturned.IsSet)return false;
            release.Set();if(!create.Join(10000) || !dispose.Join(10000))return false;
            try{backend.CreateToken("bwraaaaaaaaaaaaaaaaa","synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");}catch(System.ObjectDisposedException){rejected=true;}
            return starts==1 && rejected && !Alive(pid);
        } finally {release.Set();backend.Dispose();}
    }
}
'@
    Add-Type -TypeDefinition ($source + "`n" + $fixture)
    $executable = (Get-Process -Id $PID).Path
    foreach ($fault in @('timeout','stdout-bound','stderr-bound','slow-drip')) {
        $replacement = switch ($fault) {
            'timeout' { 'System.Threading.Thread.Sleep(5000);return 1326;' }
            'stdout-bound' { 'Console.Write(new string(''X'',20000));return 1326;' }
            'stderr-bound' { 'Console.Error.Write(new string(''E'',20000));System.Threading.Thread.Sleep(5000);return 1326;' }
            'slow-drip' { 'for(int i=0;i<10;i++){Console.Write(''1'');System.Threading.Thread.Sleep(500);}return 1326;' }
        }
        $faultPath = Write-WecProcessScript $directory $fault ($native.Replace('return 1326;', $replacement))
        Assert-Process ([BowerProcessTransportChecks]::Fault($faultPath, $executable)) ("bounded owned child: " + $fault)
    }
    Assert-Process ([BowerProcessTransportChecks]::LateRegistration($path, $executable)) 'late registration escapes disposal'
    Assert-Process ((Get-Content ($path + '.sha256') -Raw) -ceq (Get-FileHash $path).Hash.ToLowerInvariant()) 'worker provenance hash'
    if ($env:OS -eq 'Windows_NT') {
        $backend = New-Object BowerWecProcessNative -ArgumentList $path
        try {
            $owned = $backend.CreateToken('bwraaaaaaaaaaaaaaaaa', 'synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
            $backend.Impersonate($owned)
            Assert-Process ($backend.Connect('bwraaaaaaaaaaaaaaaaa', 'synthetic-invalid-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $true) -eq 1326) 'parent process connection protocol'
            Assert-Process ($backend.Cancel() -eq 2250 -and $backend.Revert() -and $backend.Close($owned)) 'parent process cleanup protocol'
        } finally { $backend.Dispose() }
    }
    $rejected = $false
    try { [void](Write-WecProcessScript $directory 'protocol' $native) } catch { $rejected = $true }
    Assert-Process $rejected 'worker script overwrite'
    $rejected = $false
    try { [void](Write-WecProcessScript $directory '../escape' $native) } catch { $rejected = $true }
    Assert-Process $rejected 'worker script path escape'
    $rejected = $false
    try { [void](Write-WecProcessScript $directory 'oversized' ('a' * 131072)) } catch { $rejected = $true }
    Assert-Process ($rejected -and -not (Test-Path (Join-Path $directory 'oversized-worker.ps1'))) 'worker script bound'
    Write-Output "WEC process protocol: $checks checks passed (simulated native child only)."
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
