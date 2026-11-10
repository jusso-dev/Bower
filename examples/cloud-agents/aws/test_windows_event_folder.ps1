# Lock down and rotate the Windows event folder exactly as the "Windows" section of
# docs/getting-started/aws-cloudwatch-agent.md says, then check the result as other accounts
# (#246). It creates two local users, changes C:\ProgramData\BowerEvents and registers a
# scheduled task, so it runs only elevated on a disposable machine, such as a CI runner:
#
#   pwsh -NoProfile -File examples/cloud-agents/aws/test_windows_event_folder.ps1
#
# The guide's PowerShell blocks are read from the Markdown and run as written. Only two lines
# change: the application account becomes a test user, and the rotation script is copied from
# this checkout instead of being downloaded.
param([switch] $DisposableMachine)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$guide = Join-Path $repo 'docs\getting-started\aws-cloudwatch-agent.md'
$dir = 'C:\ProgramData\BowerEvents'
$tool = 'C:\Program Files\BowerEvents'
$taskName = 'Bower event file rotation'

$usage = 'Run this with PowerShell 7, elevated, on a disposable Windows machine (CI, or pass -DisposableMachine).'
if ($PSVersionTable.PSVersion.Major -lt 7 -or -not $IsWindows) {
    Write-Error $usage
    exit 2
}
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated -or ($env:GITHUB_ACTIONS -ne 'true' -and -not $DisposableMachine)) {
    Write-Error $usage
    exit 2
}
if (Test-Path -LiteralPath $dir) {
    Write-Error "$dir already exists; this test needs a machine that has never had it."
    exit 2
}

function Fail([string] $message) { throw "FAIL: $message" }
function Pass([string] $message) { Write-Output "ok: $message" }

# --- The guide's Windows blocks -------------------------------------------------------------
$markdown = Get-Content -Raw -LiteralPath $guide
$section = [regex]::Match($markdown, '(?ms)^### Windows\s*$(.*?)^##+ ').Groups[1].Value
if (-not $section) { Fail 'no "### Windows" section in the guide' }
$blocks = @([regex]::Matches($section, '(?ms)^```powershell\r?\n(.*?)^```') | ForEach-Object { $_.Groups[1].Value })
function Block([string] $marker) {
    $found = @($blocks | Where-Object { $_.Contains($marker) })
    if ($found.Count -ne 1) { Fail "expected one PowerShell block containing '$marker', found $($found.Count)" }
    return $found[0]
}
function Replace-Line([string] $block, [string] $pattern, [string] $line) {
    if (-not [regex]::IsMatch($block, $pattern, 'Multiline')) { Fail "the guide no longer has a line matching $pattern" }
    return [regex]::Replace($block, $pattern, $line.Replace('$', '$$'), 'Multiline')
}
$lockDown = Block '/inheritance:r'
$check = Block 'Get-Content'
$rotation = Block 'Register-ScheduledTask'
foreach ($expected in @("Get-Content $dir\events.jsonl", "New-Item -ItemType File -Path $dir\other.jsonl")) {
    if (-not $check.Contains($expected)) { Fail "the guide's permission check no longer runs: $expected" }
}

# --- Two standard users: the application account and someone else --------------------------
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class BowerTestAccount
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out SafeAccessTokenHandle token);

    // Runs one file operation as the user and returns "ok", "denied: ..." or "error: ...".
    public static string Try(string user, string password, string action, string path)
    {
        SafeAccessTokenHandle token;
        // Network logon first (needs no desktop), then interactive.
        if (!LogonUser(user, ".", password, 3, 0, out token) && !LogonUser(user, ".", password, 2, 0, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed for " + user);
        }

        using (token)
        {
            return WindowsIdentity.RunImpersonated(token, () =>
            {
                try
                {
                    switch (action)
                    {
                        case "read": File.ReadAllText(path); break;
                        case "create": using (new FileStream(path, FileMode.CreateNew, FileAccess.Write)) { } break;
                        case "append": File.AppendAllText(path, "{\"schemaVersion\":\"1.0.0\",\"eventId\":\"" + Guid.NewGuid() + "\"}\n"); break;
                        default: throw new ArgumentException(action);
                    }

                    return "ok";
                }
                catch (UnauthorizedAccessException e) { return "denied: " + e.Message; }
                catch (Exception e) { return "error: " + e.GetType().Name + ": " + e.Message; }
            });
        }
    }
}
'@

function New-TestPassword {
    $bytes = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return 'Aa1!' + [Convert]::ToBase64String($bytes)
}
# ADSI rather than New-LocalUser: the LocalAccounts module doesn't load reliably in PowerShell 7.
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
$usersGroup = ([Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$accounts = @{}
foreach ($name in @('bwrf-app', 'bwrf-other')) {
    $password = New-TestPassword
    $user = $computer.Create('User', $name)
    $user.SetPassword($password)
    $user.Put('Description', 'Bower #246 test, removed afterwards')
    $user.SetInfo()
    ([ADSI]"WinNT://$env:COMPUTERNAME/$usersGroup,group").Add("WinNT://$env:COMPUTERNAME/$name,user")
    $accounts[$name] = $password
}
function As([string] $name, [string] $action, [string] $path) {
    return [BowerTestAccount]::Try($name, $accounts[$name], $action, $path)
}
function Sid([string] $name) {
    return ([Security.Principal.NTAccount]::new($env:COMPUTERNAME, $name)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$appSid = Sid 'bwrf-app'
$expectedSids = @('S-1-5-18', 'S-1-5-32-544', $appSid) | Sort-Object

function Assert-Acl([string] $path, [bool] $inherited) {
    $acl = Get-Acl -LiteralPath $path
    $rules = @($acl.Access)
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (Compare-Object $expectedSids $sids) {
        Fail "$path grants $($sids -join ', '); expected only SYSTEM, Administrators and the application"
    }
    if (@($rules | Where-Object { $_.IsInherited -ne $inherited }).Count) {
        Fail "$path has entries with IsInherited other than $inherited"
    }
}

try {
    # 1. Lock the folder down with the guide's commands.
    $app = "$env:COMPUTERNAME\bwrf-app"
    $script = Replace-Line $lockDown '^\$app = .*$' "`$app = '$app'"
    $listing = & ([scriptblock]::Create($script)) 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Fail "icacls failed ($LASTEXITCODE): $listing" }
    Write-Output $listing.Trim()
    if (-not (Get-Acl -LiteralPath $dir).AreAccessRulesProtected) { Fail 'inheritance is still on for the folder' }
    Assert-Acl $dir $false
    Assert-Acl "$dir\events.jsonl" $true
    Pass 'the folder grants only SYSTEM, Administrators and the application; events.jsonl inherits that'

    # 2. The guide's check, as a standard user who isn't the application account.
    $read = As 'bwrf-other' 'read' "$dir\events.jsonl"
    $create = As 'bwrf-other' 'create' "$dir\other.jsonl"
    foreach ($result in @($read, $create)) {
        if (-not $result.StartsWith('denied: ') -or -not $result.Contains('Access to the path')) { Fail "another user was not refused: $result" }
    }
    Pass "another standard user can't read events.jsonl or create a file in the folder ($read)"
    foreach ($attempt in 1..2) {
        $result = As 'bwrf-app' 'append' "$dir\events.jsonl"
        if ($result -ne 'ok') { Fail "the application account could not append: $result" }
    }
    Pass 'the application account appends to events.jsonl'

    # 3. Register the rotation task with the guide's commands, and run it as SYSTEM.
    $source = Join-Path $repo 'examples\cloud-agents\aws\rotate-bower-events.ps1'
    $script = Replace-Line $rotation '^Invoke-WebRequest "\$base/rotate-bower-events\.ps1".*$' `
        "Copy-Item -LiteralPath '$source' -Destination `"`$tool\rotate-bower-events.ps1`""
    & ([scriptblock]::Create($script)) | Out-Null

    function Invoke-Rotation {
        # LastRunTime has one-second resolution: start in a later second than the last run.
        Start-Sleep -Milliseconds 1100
        $before = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(90)
        do {
            Start-Sleep -Milliseconds 500
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            $running = (Get-ScheduledTask -TaskName $taskName).State -eq 'Running'
        } while ((Get-Date) -lt $deadline -and ($running -or $info.LastRunTime -eq $before))
        if ($running -or $info.LastRunTime -eq $before) { Fail 'the rotation task did not finish within 90 seconds' }
        return $info.LastTaskResult
    }
    function Lines([string] $path) { return @(Get-Content -LiteralPath $path).Count }

    $code = Invoke-Rotation
    if ($code -ne 0) { Fail "the rotation task failed with $code" }
    if ((Lines "$dir\events.jsonl.1") -ne 2) { Fail 'events.jsonl.1 does not hold the two events' }
    if ((Get-Item -LiteralPath "$dir\events.jsonl").Length -ne 0) { Fail 'the new events.jsonl is not empty' }
    Assert-Acl "$dir\events.jsonl" $true
    Assert-Acl "$dir\events.jsonl.1" $true
    $result = As 'bwrf-app' 'append' "$dir\events.jsonl"
    if ($result -ne 'ok') { Fail "the application account could not append after rotation: $result" }
    $result = As 'bwrf-other' 'read' "$dir\events.jsonl.1"
    if (-not $result.StartsWith('denied: ')) { Fail "another user can read the rotated file: $result" }
    Pass 'the task rotates as SYSTEM; the new file inherits the lockdown and the application keeps appending'

    # 4. A writer holding the file open without delete sharing: the run fails and changes nothing.
    $rotated = (Get-FileHash -LiteralPath "$dir\events.jsonl.1").Hash
    $holder = [IO.FileStream]::new("$dir\events.jsonl", 'Open', 'Write', 'ReadWrite')
    try {
        $code = Invoke-Rotation
    } finally {
        $holder.Dispose()
    }
    if ($code -eq 0) { Fail 'the rotation task succeeded while a writer held the file open' }
    if ((Get-FileHash -LiteralPath "$dir\events.jsonl.1").Hash -ne $rotated) { Fail 'events.jsonl.1 changed during a failed run' }
    if (Test-Path -LiteralPath "$dir\events.jsonl.2") { Fail 'older copies were shifted during a failed run' }
    if ((Lines "$dir\events.jsonl") -ne 1) { Fail 'events.jsonl lost its event during a failed run' }
    $code = Invoke-Rotation
    if ($code -ne 0) { Fail "the next run failed with $code" }
    if ((Get-FileHash -LiteralPath "$dir\events.jsonl.2").Hash -ne $rotated) { Fail 'the next run did not shift events.jsonl.1 to .2' }
    Pass "a run that finds the file held open fails (task result $code) without changing anything, and the next run rotates"

    # 5. A run cut short after its first rename is finished by the next run.
    Set-Content -LiteralPath "$dir\events.jsonl.rotating" -Value 'cut-short'
    $result = As 'bwrf-app' 'append' "$dir\events.jsonl"
    if ($result -ne 'ok') { Fail "the application account could not append: $result" }
    $code = Invoke-Rotation
    if ($code -ne 0) { Fail "the run after an interrupted one failed with $code" }
    if ((Get-Content -LiteralPath "$dir\events.jsonl.1") -ne 'cut-short') { Fail 'the interrupted rotation was not finished' }
    if ((Lines "$dir\events.jsonl") -ne 1) { Fail 'the live file was touched while finishing an interrupted rotation' }
    if (Test-Path -LiteralPath "$dir\events.jsonl.rotating") { Fail 'events.jsonl.rotating was left behind' }
    Pass 'a run cut short after its first rename is finished by the next run'

    # 6. Seven copies are kept, newest first; an empty file is left alone.
    for ($run = 1; $run -le 8; $run++) {
        Set-Content -LiteralPath "$dir\events.jsonl" -Value "run-$run"
        if ((Invoke-Rotation) -ne 0) { Fail "rotation run $run failed" }
    }
    if (Test-Path -LiteralPath "$dir\events.jsonl.8") { Fail 'more than seven copies are kept' }
    if ((Get-Content -LiteralPath "$dir\events.jsonl.1") -ne 'run-8' -or (Get-Content -LiteralPath "$dir\events.jsonl.7") -ne 'run-2') {
        Fail 'the copies are not newest first'
    }
    $code = Invoke-Rotation
    if ((Get-Content -LiteralPath "$dir\events.jsonl.1") -ne 'run-8') { Fail 'an empty events.jsonl was rotated' }
    Pass 'seven copies are kept, newest first, and an empty file is not rotated'
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $dir, $tool -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($name in @('bwrf-app', 'bwrf-other')) {
        try { $computer.Delete('User', $name) } catch { Write-Warning "could not remove the test user ${name}: $_" }
    }
}
