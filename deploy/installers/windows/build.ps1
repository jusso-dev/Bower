<#
.SYNOPSIS
Builds the Bower collector MSI and the Windows offline bundle from a `publish` job artefact.

.DESCRIPTION
Runs in CI on windows-latest with WiX v5 (`wix` .NET tool) on PATH. When
BOWER_SIGN_PFX_FILE and BOWER_SIGN_PFX_PASSWORD are set, the executables and the MSI
are Authenticode-signed (certificate imported into the CurrentUser store, so the
password never reaches a command line) and timestamped; otherwise the bundle carries
UNSIGNED.txt.

.PARAMETER ArtefactDirectory
The bower-<rid> artefact (collector\ and cli\ folders).

.PARAMETER Architecture
x64 or arm64.

.PARAMETER Version
Semantic version, for example 0.1.0 or 0.1.0-dev.42.

.PARAMETER OutputDirectory
Where the MSI and the offline zip are written.

.EXAMPLE
pwsh -File deploy/installers/windows/build.ps1 -ArtefactDirectory artefacts/bower-win-x64 -Architecture x64 -Version 0.1.0 -OutputDirectory dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ArtefactDirectory,
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$')][string] $Version,
    [Parameter(Mandatory)][string] $OutputDirectory
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here '../../..')).Path
$dist = (Resolve-Path $ArtefactDirectory).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$out = (Resolve-Path $OutputDirectory).Path

# MSI versions are numeric: 0.1.0-dev.42 becomes 0.1.0.42 (the fourth field is ignored
# when comparing upgrades, so builds of one version upgrade each other in place).
$core = $Version.Split('-')[0]
$msiVersion = $core
if ($Version -match '\.(\d+)$' -and $Version.Contains('-')) {
    $msiVersion = "$core.$($Matches[1])"
}

function Invoke-Signing {
    param([string] $Tool, [string] $Thumbprint, [string[]] $Path)
    $timestamp = if ($env:BOWER_SIGN_TIMESTAMP_URL) { $env:BOWER_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
    & $Tool sign /sha1 $Thumbprint /s My /fd sha256 /tr $timestamp /td sha256 @Path
    if ($LASTEXITCODE -ne 0) { throw "signtool failed with $LASTEXITCODE." }
}

foreach ($file in 'collector\Bower.Collector.exe', 'collector\e_sqlite3.dll', 'cli\bower.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $dist $file))) { throw "Missing $file in $dist." }
}

$signing = [bool]($env:BOWER_SIGN_PFX_FILE -and $env:BOWER_SIGN_PFX_PASSWORD)
$certificate = $null
$signtool = ''
if ($signing) {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'UserKeySet, PersistKeySet'
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $env:BOWER_SIGN_PFX_FILE, $env:BOWER_SIGN_PFX_PASSWORD, $flags)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($certificate)
    $store.Close()
    $signtool = (Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
            Sort-Object FullName | Select-Object -Last 1).FullName
    if (-not $signtool) { throw 'signtool.exe not found.' }
    Invoke-Signing -Tool $signtool -Thumbprint $certificate.Thumbprint -Path @(
        (Join-Path $dist 'collector\Bower.Collector.exe'), (Join-Path $dist 'cli\bower.exe'))
}

$msi = Join-Path $out "bower-collector-$Version-$Architecture.msi"
& wix build -arch $Architecture -d "Version=$msiVersion" -d "Dist=$dist" `
    -d "Policies=$(Join-Path $repo 'policies\default')" -o $msi (Join-Path $here 'Bower.wxs')
if ($LASTEXITCODE -ne 0) { throw "wix build failed with $LASTEXITCODE." }
if ($signing) {
    Invoke-Signing -Tool $signtool -Thumbprint $certificate.Thumbprint -Path @($msi)
}

# Offline bundle: the MSI, the installer script and a seed folder for the operator.
$name = "bower-collector-offline-$Version-win-$Architecture"
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
$bundle = Join-Path $stage $name
New-Item -ItemType Directory -Force -Path (Join-Path $bundle 'seed') | Out-Null
try {
    Copy-Item -LiteralPath $msi -Destination $bundle
    Copy-Item -LiteralPath (Join-Path $here 'Install-BowerCollector.ps1') -Destination $bundle
    Copy-Item -LiteralPath (Join-Path $here 'README.txt') -Destination $bundle
    Set-Content -LiteralPath (Join-Path $bundle 'seed\README.txt') -Encoding utf8 -Value @(
        'Put enrolment-token, pack-trusted.pem, command-trusted.pem and packs\*.bowerpack here.',
        'See ..\README.txt.')
    if (-not $signing) {
        Set-Content -LiteralPath (Join-Path $bundle 'UNSIGNED.txt') -Encoding utf8 -Value `
            'This MSI is NOT signed: the build had no code-signing certificate. Verify it by checksum from a trusted channel.'
    }
    $hash = (Get-FileHash -LiteralPath (Join-Path $bundle (Split-Path $msi -Leaf)) -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS.txt') -Encoding ascii -Value "$hash  $(Split-Path $msi -Leaf)"
    Compress-Archive -Path $bundle -DestinationPath (Join-Path $out "$name.zip") -Force
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    if ($certificate) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force }
}
Get-ChildItem -LiteralPath $out | Format-Table Name, Length -AutoSize | Out-String | Write-Information -InformationAction Continue
