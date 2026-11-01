# Real Windows/NTFS fixture. Only unique temporary files are changed; no live Bower
# files, services, queue, credentials, AWS calls or SMB sessions are touched.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'native-windows-required' }
if (-not (Get-Command Invoke-CandidateSwap -ErrorAction SilentlyContinue)) {
    $path = Join-Path $PSScriptRoot '../monitoring/update-candidate-windows.ps1'
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'candidate-parse' }
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
}
$serviceSid = 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086'
$root = Join-Path 'C:\ProgramData' ('BowerCandidateAclFixture-' + [Guid]::NewGuid().ToString('N'))
New-CandidatePrivateDirectory $root
$tests = 0
$cases = New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($scenario in 'success', 'failed-readiness', 'partial-replace', 'rollback-not-ready') {
        $caseRoot = Join-Path $root $scenario
        New-CandidatePrivateDirectory $caseRoot
        $install = Join-Path $caseRoot 'install'
        New-CandidatePrivateDirectory $install
        $directoryAcl = Get-Acl -LiteralPath $install
        $directoryAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        $directoryAcl.SetGroup((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
        $directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($serviceSid)), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        Set-Acl -LiteralPath $install -AclObject $directoryAcl
        $candidate = Join-Path $caseRoot 'candidate'; New-CandidatePrivateDirectory $candidate
        $backup = Join-Path $caseRoot 'backup'; New-CandidatePrivateDirectory $backup
        $expectedAcls = @{}
        foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
            [IO.File]::WriteAllText((Join-Path $install $name), "old-$name")
            [IO.File]::WriteAllText((Join-Path $candidate $name), "new-$name")
            $acl = Get-Acl -LiteralPath (Join-Path $install $name)
            $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
            $acl.SetGroup((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
            Set-Acl -LiteralPath (Join-Path $install $name) -AclObject $acl
            $acl = Get-Acl -LiteralPath (Join-Path $install $name)
            $serviceRules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -ceq $serviceSid })
            if ($acl.AreAccessRulesProtected -or $serviceRules.Count -ne 1 -or -not $serviceRules[0].IsInherited) { throw 'fixture-must-start-with-inherited-service-rx' }
            $sourceAcl = Get-Acl -LiteralPath (Join-Path $candidate $name)
            if (@($sourceAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -ceq $serviceSid }).Count -ne 0) { throw 'fixture-staging-must-be-private' }
            $expectedAcls[$name] = Get-CandidateExpectedAcl (Join-Path $install $name) $serviceSid
            $tests++
        }
        $protect = { param($Path, $Name) Set-CandidateNativeAcl $Path $expectedAcls[$Name] }
        $verify = { param($Path, $Name) Assert-CandidateNativeAcl $Path $expectedAcls[$Name] }
        $script:healthCalls = 0; $script:stopCalls = 0; $script:startCalls = 0
        $stop = { $script:stopCalls++ }
        if ($scenario -eq 'partial-replace') {
            $stop = { $script:stopCalls++; if ($script:stopCalls -eq 1) { Remove-Item (Join-Path $candidate 'e_sqlite3.dll') } }
        }
        $start = {
            foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') { Assert-CandidateNativeAcl (Join-Path $install $name) $expectedAcls[$name] }
            $script:startCalls++
        }
        $health = { $script:healthCalls++; return $true }
        if ($scenario -eq 'failed-readiness') { $health = { $script:healthCalls++; return $script:healthCalls -gt 1 } }
        if ($scenario -eq 'rollback-not-ready') { $health = { return $false } }
        $result = Invoke-CandidateSwap $install $candidate $backup $stop $start $health $protect $verify
        if ($result.updated -ne ($scenario -eq 'success')) { throw 'fixture-update-status' }
        if ($scenario -in @('failed-readiness', 'partial-replace') -and -not $result.rollbackSucceeded) { throw 'fixture-rollback-status' }
        if ($scenario -eq 'rollback-not-ready' -and $result.rollbackSucceeded) { throw 'fixture-false-rollback-success' }
        $prefix = if ($scenario -eq 'success') { 'new-' } else { 'old-' }
        foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
            if ([IO.File]::ReadAllText((Join-Path $install $name)) -cne ($prefix + $name)) { throw 'fixture-file-content' }
            Assert-CandidateNativeAcl (Join-Path $install $name) $expectedAcls[$name]
            Assert-CandidateNativeAcl (Join-Path $backup $name) $expectedAcls[$name]
            $tests++
        }
        $cases.Add($scenario)
    }
    # Fail closed on broad access, a missing service grant, or service write access.
    foreach ($scenario in 'extra-users', 'missing-service', 'service-write') {
        $path = Join-Path $root ($scenario + '.fixture')
        [IO.File]::WriteAllText($path, 'fixture')
        $acl = New-CandidateNativeAcl 'S-1-5-32-544' 'S-1-5-18' $serviceSid
        if ($scenario -eq 'extra-users') {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'Allow')))
        } else {
            $acl.PurgeAccessRules((New-Object Security.Principal.SecurityIdentifier($serviceSid)))
            if ($scenario -eq 'service-write') {
                $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                    (New-Object Security.Principal.SecurityIdentifier($serviceSid)), 'Modify', 'Allow')))
            }
        }
        Set-Acl -LiteralPath $path -AclObject $acl
        $before = Get-CandidateAclFingerprint (Get-Acl -LiteralPath $path)
        $rejected = $false
        try { Get-CandidateExpectedAcl $path $serviceSid | Out-Null } catch { $rejected = $true }
        if (-not $rejected -or (Get-CandidateAclFingerprint (Get-Acl -LiteralPath $path)) -cne $before) { throw 'fixture-unknown-acl-not-rejected-readonly' }
        $tests++; $cases.Add($scenario)
    }
    @{ nativeAclFixture = 'passed'; checks = $tests; cases = @($cases);
        powershellVersion = $PSVersionTable.PSVersion.ToString(); inheritedBaselineTested = $true;
        privateCandidateAndRollbackTested = $true; liveBowerModified = $false } | ConvertTo-Json -Depth 3 -Compress
} catch {
    @{ nativeAclFixture = 'failed'; checksCompleted = $tests; failure = (Get-CandidateFailure $_); liveBowerModified = $false } |
        ConvertTo-Json -Depth 4 -Compress
    exit 1
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
