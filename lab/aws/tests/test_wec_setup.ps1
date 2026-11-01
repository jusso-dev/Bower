# Cross-platform validation tests. Never dot-source the installer or execute host actions.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path $PSScriptRoot '../monitoring'
$tests = 0
foreach ($name in 'setup-wec-qualification.ps1', 'wec-qualification.ps1', 'wec-destination-outage.ps1', 'export-wec-evidence.ps1') {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $name), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "parse: $name" }
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
}
# Native/FQID diagnostics must never echo arbitrary exception text or IDs.
try { throw 'aws-cli-required' } catch { $safe = Get-WecSafeFailure $_ }
if ($safe.staticCode -cne 'aws-cli-required' -or $safe.fullyQualifiedErrorId -cne 'aws-cli-required' -or $safe.scriptLine -lt 1) { throw 'static diagnostic lost' }; $tests++
try { throw 'synthetic-secret-must-not-leak' } catch { $safe = Get-WecSafeFailure $_ }
if (($safe | ConvertTo-Json -Compress) -match 'synthetic-secret' -or $safe.staticCode -cne 'unclassified' -or $safe.fullyQualifiedErrorId -cne 'redacted-unrecognized') { throw 'unsafe diagnostic' }; $tests++
$fake = New-Object Management.Automation.ErrorRecord ([InvalidOperationException]::new('synthetic-secret-must-not-leak')), 'NativeCommandError', ([Management.Automation.ErrorCategory]::NotSpecified), $null
$safe = Get-WecSafeFailure $fake
if ($safe.fullyQualifiedErrorId -cne 'NativeCommandError' -or ($safe | ConvertTo-Json -Compress) -match 'synthetic-secret') { throw 'native diagnostic' }; $tests++

function Test-WecRejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'invalid input accepted' }
    $script:tests++
}
function Get-TestManifest {
    $files = @{}
    foreach ($name in 'collector.zip', 'sentinel.json', 'ingest.pem', 'ingest-token', 'hmac.key',
        'windows-security-logon-1.0.2.bowerpack', 'pack-signing.pub.pem', 'collector-health.yaml', 'Test-BowerCollectorHealth.ps1') {
        $files[$name] = @{ sha256 = ('a' * 64); bytes = 1 }
    }
    return (@{ schemaVersion = 1; runId = 'bower-ws6-20261101-010101'; role = 'windows'; files = $files } | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
}
$run = 'bower-ws6-20261101-010101'
$manifest = Get-TestManifest
if ((Assert-WecManifest $manifest $run).Count -ne 9) { throw 'valid manifest refused' }; $tests++
Test-WecRejected { Assert-WecManifest $manifest 'bower-ws6-20261101-010102' }
foreach ($change in 'role', 'extra', 'hash', 'large', 'fraction', 'unknown') {
    $manifest = Get-TestManifest
    switch ($change) {
        role { $manifest.role = 'sender' }
        extra { $manifest | Add-Member -NotePropertyName surprise -NotePropertyValue 1 }
        hash { $manifest.files.'collector.zip'.sha256 = '../escape' }
        large { $manifest.files.'ingest-token'.bytes = 4097 }
        fraction { $manifest.files.'ingest-token'.bytes = 1.5 }
        unknown { $manifest.files | Add-Member -NotePropertyName '../escape' -NotePropertyValue @{ sha256 = ('a' * 64); bytes = 1 } }
    }
    Test-WecRejected { Assert-WecManifest $manifest $run }
}
$settings = [pscustomobject]@{ client = '11111111-1111-1111-1111-111111111111';
    tenant = 'f4f33fb1-b681-40d1-a854-6f888d45b891'; dcr = 'dcr-' + ('a' * 32);
    dce = 'https://synthetic.australiaeast-1.ingest.monitor.azure.com' }
if ((Read-WecDestination $settings).Count -ne 8) { throw 'destination refused' }; $tests++
foreach ($endpoint in 'http://synthetic.ingest.monitor.azure.com', 'https://user:password@synthetic.ingest.monitor.azure.com',
    'https://synthetic.ingest.monitor.azure.com.evil.invalid', 'https://synthetic.ingest.monitor.azure.com/path') {
    $settings.dce = $endpoint
    Test-WecRejected { Read-WecDestination $settings }
}
# Resolve the enum explicitly before invoking ZipFile on Windows PowerShell 5.1.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$temp = Join-Path ([IO.Path]::GetTempPath()) ('bower-wec-validation-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp | Out-Null
function New-TestArchive {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Names, [int]$Mode = 0)
    $path = Join-Path $temp ([Guid]::NewGuid().ToString('N') + '.zip')
    if (-not $PSCmdlet.ShouldProcess($path, 'Create temporary test archive')) { return }
    $archive = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Names) {
            $entry = $archive.CreateEntry($name)
            if ($Mode) { $entry.ExternalAttributes = $Mode }
            if (-not $name.EndsWith('/')) { $stream = $entry.Open(); try { $stream.WriteByte(42) } finally { $stream.Dispose() } }
        }
    } finally { $archive.Dispose() }
    return $path
}
try {
    $path = New-TestArchive @('collector/', 'collector/Bower.Collector.exe', 'collector/assets/', 'collector/assets/policy.json')
    Assert-WecArchive $path; $tests++
    Expand-WecArchive $path (Join-Path $temp 'expanded')
    if ([IO.File]::ReadAllBytes((Join-Path $temp 'expanded/collector/Bower.Collector.exe'))[0] -ne 42) { throw 'extraction failed' }; $tests++
    foreach ($name in '../escape', '/collector/escape', 'collector/../escape', 'collector/./escape', 'collector\\escape',
        'collector/NUL.txt', 'collector/COM1', 'collector/file:stream', 'collector/trailing.', 'collector/trailing ',
        'collector/bower.collector.EXE', 'collector/Bower.Collector.exe') {
        $path = New-TestArchive @('collector/Bower.Collector.exe', $name)
        Test-WecRejected { Assert-WecArchive $path }
    }
    $path = New-TestArchive @('collector/Bower.Collector.exe') -Mode -1577123840
    Test-WecRejected { Assert-WecArchive $path }
    $path = New-TestArchive @('collector/Bower.Collector.exe') -Mode 1024
    Test-WecRejected { Assert-WecArchive $path }
    $path = New-TestArchive @('collector/Bower.Collector.exe', 'collector/dir', 'collector/dir/file')
    Test-WecRejected { Assert-WecArchive $path }
    $path = New-TestArchive @('collector/other.exe')
    Test-WecRejected { Assert-WecArchive $path }
    $path = New-TestArchive @('collector/Bower.Collector.exe', '../escape')
    Test-WecRejected { Expand-WecArchive $path (Join-Path $temp 'rejected') }
    if (Test-Path (Join-Path $temp 'rejected')) { throw 'extracted invalid archive' }; $tests++
    Add-WecGenerator
    Test-WecRejected { [BowerWecNetworkGenerator]::Run('unused', 101, 1, 'unused') }
    Test-WecRejected { [BowerWecNetworkGenerator]::Run('unused', 100, 501, 'unused') }
} finally { Remove-Item $temp -Recurse -Force }
Write-Output "WEC artifact and generator validation: $tests checks passed (no Windows host actions executed)."
