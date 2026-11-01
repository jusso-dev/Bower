# Pure archive/file transaction tests. ACL callbacks are explicitly mocked here.
# Run test_candidate_update_native_acl.ps1 on Windows for real NTFS ACL coverage.
# No services, AWS commands or host mutations.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path $PSScriptRoot '../monitoring/update-candidate-windows.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'candidate parse' }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
# Windows PowerShell 5.1 does not resolve ZipArchiveMode merely by loading ZipFile.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = Join-Path ([IO.Path]::GetTempPath()) ('bower-candidate-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
$tests = 0
function New-ZipFixture([string]$Extra, [int]$Mode = 0) {
    $path = Join-Path $root ([Guid]::NewGuid().ToString('N') + '.zip')
    $archive = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $names = @('collector/Bower.Collector.exe', 'collector/e_sqlite3.dll')
        if ($Extra) { $names += $Extra }
        foreach ($name in $names) {
            $entry = $archive.CreateEntry($name)
            $entry.ExternalAttributes = $Mode
            $stream = $entry.Open(); try { $stream.WriteByte(42) } finally { $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
    return $path
}
try {
    foreach ($extra in '', '../escape', 'collector/settings.json', 'collector/bower.collector.EXE', 'collector/Bower.Collector.exe') {
        $archive = New-ZipFixture $extra
        $destination = Join-Path $root ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $destination | Out-Null
        $failed = $false
        try { Expand-CandidateArchive $archive $destination } catch { $failed = $true }
        if ($failed -ne [bool]$extra) { throw 'candidate archive validation' }; $tests++
    }
    $archive = New-ZipFixture '' -1577123840
    $failed = $false
    try { Expand-CandidateArchive $archive $root } catch { $failed = $true }
    if (-not $failed) { throw 'candidate symlink accepted' }; $tests++
    foreach ($scenario in 'success', 'bad-start', 'partial-replace', 'bad-rollback') {
        $testRoot = Join-Path $root $scenario
        New-Item -ItemType Directory $testRoot | Out-Null
        foreach ($directory in 'install', 'candidate', 'backup') { New-Item -ItemType Directory (Join-Path $testRoot $directory) | Out-Null }
        foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
            [IO.File]::WriteAllText((Join-Path $testRoot "install/$name"), "old-$name")
            [IO.File]::WriteAllText((Join-Path $testRoot "candidate/$name"), "new-$name")
        }
        [IO.File]::WriteAllText((Join-Path $testRoot 'install/config'), 'unchanged')
        $script:healthCalls = 0
        $health = { $script:healthCalls++; return $true }
        if ($scenario -eq 'bad-start') { $health = { $script:healthCalls++; return $script:healthCalls -gt 1 } }
        if ($scenario -eq 'bad-rollback') { $health = { return $false } }
        $stop = { }
        if ($scenario -eq 'partial-replace') {
            # Hash candidate first, then remove its second file when stopping to
            # inject a second-swap failure after the executable was replaced.
            $script:stopCalls = 0
            $stop = { $script:stopCalls++; if ($script:stopCalls -eq 1) { Remove-Item (Join-Path $testRoot 'candidate/e_sqlite3.dll') } }
        }
        $result = Invoke-CandidateSwap (Join-Path $testRoot 'install') (Join-Path $testRoot 'candidate') (Join-Path $testRoot 'backup') $stop { } $health { param($Path, $Name) } { param($Path, $Name) }
        if ($result.updated -ne ($scenario -eq 'success')) { throw 'incorrect update success' }
        if ($scenario -in @('bad-start', 'partial-replace') -and -not $result.rollbackSucceeded) { throw 'rollback failed' }
        if ($scenario -eq 'bad-rollback' -and $result.rollbackSucceeded) { throw 'false rollback success' }
        $prefix = if ($scenario -eq 'success') { 'new-' } else { 'old-' }
        foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
            if ([IO.File]::ReadAllText((Join-Path $testRoot "install/$name")) -cne ($prefix + $name)) { throw 'incorrect installed bytes' }
        }
        if ([IO.File]::ReadAllText((Join-Path $testRoot 'install/config')) -cne 'unchanged') { throw 'unrelated config changed' }
        $tests++
    }
} finally { Remove-Item $root -Recurse -Force }
Write-Output "Windows candidate validation: $tests checks passed (services/AWS not invoked)."
