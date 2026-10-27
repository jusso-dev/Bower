<#
.SYNOPSIS
Silently installs the Bower collector MSI and applies a pre-seeded enrolment token and
trusted keys (#112). Runs on Windows PowerShell 5.1 and PowerShell 7.

.DESCRIPTION
The offline installer for Windows. It installs the MSI with msiexec /qn (no secret is
ever an MSI property, because MSI logs properties), then:

- copies the trusted pack and command keys into %ProgramData%\Bower\keys and points the
  service at them;
- writes the one-time enrolment token into %ProgramData%\Bower\enrolment (the folder only
  SYSTEM, Administrators and NT SERVICE\Bower can read) and deletes the source file;
- restarts the service and waits until the collector recorded the token as consumed
  (it is then Pending approval) or refused. The collector deletes its copy of the token.

Use it from Intune (Win32 app), ConfigMgr or a GPO startup script. Plain
`msiexec /i bower-collector.msi /qn MANAGEMENTENDPOINT=...` works too when the token is
placed separately.

.PARAMETER MsiPath
The MSI. Default: the only bower-collector-*.msi next to this script.

.PARAMETER ManagementEndpoint
Management API URL (HTTPS, or HTTP to loopback only). Required with a token.

.PARAMETER CollectorId
Collector id. Default: the computer name.

.PARAMETER Environment
Environment name the enrolment token is bound to.

.PARAMETER EnrolmentTokenFile
File holding the one-time bwe1 token. Default: seed\enrolment-token. Deleted after it
is copied into place.

.PARAMETER PackTrustedKeyFile
Public key trusted to sign packs. Default: seed\pack-trusted.pem when present.

.PARAMETER CommandTrustedKeyFile
Public key trusted to sign management commands. Default: seed\command-trusted.pem.

.PARAMETER WaitSeconds
How long to wait for the enrolment outcome. 0 skips the wait.

.PARAMETER RequireSignature
Refuse an MSI without a valid Authenticode signature.

.PARAMETER LogPath
msiexec verbose log. Holds no secret values.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BowerCollector.ps1 -ManagementEndpoint https://bower-management.example.com/ -Environment production -RequireSignature

Exit codes: 0 installed (and enrolled, Pending approval, with a token), 2 invalid input,
3 management refused the token, 4 enrolment not confirmed in time, other values come
from msiexec.
#>
[CmdletBinding()]
param(
    [string] $MsiPath,
    [string] $ManagementEndpoint,
    [string] $CollectorId,
    [string] $Environment,
    [string] $EnrolmentTokenFile,
    [string] $PackTrustedKeyFile,
    [string] $CommandTrustedKeyFile,
    [ValidateRange(0, 3600)]
    [int] $WaitSeconds = 120,
    [switch] $RequireSignature,
    [string] $LogPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'bower-collector-install.log')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:MaximumTokenBytes = 1024
$script:TokenPattern = '^bwe1\.[A-Za-z0-9]+\.[A-Za-z0-9_-]+$'
# Property values go on the msiexec command line: no quotes, spaces or MSI brackets.
$script:SafeValuePattern = '^[A-Za-z0-9._:/\\@%+=,~-]*\z'

function Test-BowerSafeValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string] $Value)
    return $Value -match $script:SafeValuePattern
}

function Read-BowerEnrolmentToken {
    <# Returns the trimmed token, or throws when the file is oversized or not a bwe1 token. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Path)
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -eq 0 -or $item.Length -gt $script:MaximumTokenBytes) {
        throw 'The enrolment token file is empty or too large.'
    }
    $token = ([System.IO.File]::ReadAllText($item.FullName)).Trim()
    if ($token -notmatch $script:TokenPattern) {
        throw 'The enrolment token file does not hold a bwe1 token.'
    }
    return $token
}

function Test-BowerManagementEndpoint {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string] $Endpoint)
    $uri = $null
    if (-not [System.Uri]::TryCreate($Endpoint, [System.UriKind]::Absolute, [ref] $uri)) {
        return $false
    }
    if ($uri.UserInfo -or $uri.Query) {
        return $false
    }
    if ($uri.Scheme -eq 'https') {
        return $true
    }
    return $uri.Scheme -eq 'http' -and ($uri.IsLoopback)
}

function Get-BowerSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    }
    finally {
        $sha.Dispose()
    }
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-BowerMsiArgument {
    <# The msiexec argument list. Only public, non-secret properties. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string] $Msi,
        [Parameter(Mandatory)][string] $Log,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Property
    )
    $arguments = @('/i', ('"{0}"' -f $Msi), '/qn', '/norestart', '/l*v', ('"{0}"' -f $Log))
    foreach ($name in ($Property.Keys | Sort-Object)) {
        $value = [string] $Property[$name]
        if ($name -notmatch '^[A-Z]+$' -or -not (Test-BowerSafeValue -Value $value)) {
            throw "Unsupported characters in MSI property $name."
        }
        if ($value) {
            $arguments += ('{0}={1}' -f $name, $value)
        }
    }
    return $arguments
}

function Install-BowerCollector {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [string] $MsiPath,
        [string] $ManagementEndpoint,
        [string] $CollectorId,
        [string] $Environment,
        [string] $EnrolmentTokenFile,
        [string] $PackTrustedKeyFile,
        [string] $CommandTrustedKeyFile,
        [int] $WaitSeconds = 120,
        [switch] $RequireSignature,
        [string] $LogPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'bower-collector-install.log')
    )
    $here = $PSScriptRoot
    $seed = Join-Path $here 'seed'
    $data = Join-Path $env:ProgramData 'Bower'

    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error 'Run as an administrator (or SYSTEM).' -ErrorAction Continue
        return 2
    }

    if (-not $MsiPath) {
        $found = @(Get-ChildItem -LiteralPath $here -Filter 'bower-collector-*.msi' -File)
        if ($found.Count -ne 1) {
            Write-Error 'Pass -MsiPath: expected exactly one bower-collector-*.msi next to this script.' -ErrorAction Continue
            return 2
        }
        $MsiPath = $found[0].FullName
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $MsiPath
    if ($signature.Status -ne 'Valid') {
        if ($RequireSignature) {
            Write-Error "The MSI signature is not valid ($($signature.Status))." -ErrorAction Continue
            return 2
        }
        Write-Warning "The MSI is not signed with a valid Authenticode signature ($($signature.Status))."
    }

    if (-not $EnrolmentTokenFile) { $EnrolmentTokenFile = Join-Path $seed 'enrolment-token' }
    if (-not $PackTrustedKeyFile) { $PackTrustedKeyFile = Join-Path $seed 'pack-trusted.pem' }
    if (-not $CommandTrustedKeyFile) { $CommandTrustedKeyFile = Join-Path $seed 'command-trusted.pem' }

    $token = $null
    if (Test-Path -LiteralPath $EnrolmentTokenFile -PathType Leaf) {
        try {
            $token = Read-BowerEnrolmentToken -Path $EnrolmentTokenFile
        }
        catch {
            Write-Error $_.Exception.Message -ErrorAction Continue
            return 2
        }
        if (-not $ManagementEndpoint) {
            Write-Error 'An enrolment token needs -ManagementEndpoint.' -ErrorAction Continue
            return 2
        }
    }
    if ($ManagementEndpoint -and -not (Test-BowerManagementEndpoint -Endpoint $ManagementEndpoint)) {
        Write-Error 'ManagementEndpoint must be an HTTPS URL (HTTP only to loopback) without credentials or a query.' -ErrorAction Continue
        return 2
    }

    $keys = Join-Path $data 'keys'
    $packs = Join-Path $data 'packs'
    $properties = [ordered]@{
        MANAGEMENTENDPOINT = $ManagementEndpoint
        COLLECTORID        = $CollectorId
        BOWERENVIRONMENT   = $Environment
    }
    if (Test-Path -LiteralPath $PackTrustedKeyFile -PathType Leaf) {
        $properties.PACKTRUSTEDKEYS = Join-Path $keys 'pack-trusted.pem'
    }
    if (Test-Path -LiteralPath $CommandTrustedKeyFile -PathType Leaf) {
        $properties.COMMANDTRUSTEDKEYS = Join-Path $keys 'command-trusted.pem'
    }
    $seedPacks = @()
    if (Test-Path -LiteralPath (Join-Path $seed 'packs') -PathType Container) {
        $seedPacks = @(Get-ChildItem -LiteralPath (Join-Path $seed 'packs') -Filter '*.bowerpack' -File | Sort-Object Name)
    }
    if ($seedPacks.Count -gt 0) {
        $properties.PACKS = ($seedPacks | ForEach-Object { Join-Path $packs $_.Name }) -join ','
    }

    try {
        $arguments = Get-BowerMsiArgument -Msi $MsiPath -Log $LogPath -Property $properties
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Continue
        return 2
    }
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        Write-Error "msiexec failed with exit code $($process.ExitCode); see $LogPath." -ErrorAction Continue
        return $process.ExitCode
    }

    # Keys and packs inherit the folder ACL: Administrators change them, the service reads.
    if ($properties.Contains('PACKTRUSTEDKEYS')) {
        Copy-Item -LiteralPath $PackTrustedKeyFile -Destination $properties.PACKTRUSTEDKEYS -Force
    }
    if ($properties.Contains('COMMANDTRUSTEDKEYS')) {
        Copy-Item -LiteralPath $CommandTrustedKeyFile -Destination $properties.COMMANDTRUSTEDKEYS -Force
    }
    foreach ($pack in $seedPacks) {
        Copy-Item -LiteralPath $pack.FullName -Destination (Join-Path $packs $pack.Name) -Force
    }

    $tokenHash = $null
    if ($token) {
        # A new file inherits the enrolment folder ACL (SYSTEM, Administrators, the service).
        $target = Join-Path (Join-Path $data 'enrolment') 'enrolment-token'
        [System.IO.File]::WriteAllText($target, $token, (New-Object System.Text.UTF8Encoding($false)))
        $tokenHash = Get-BowerSha256Hex -Text $token
        Remove-Item -LiteralPath $EnrolmentTokenFile -Force
        $token = $null
    }

    Restart-Service -Name 'Bower'
    Write-Information 'Bower collector installed; service Bower restarted.' -InformationAction Continue
    if (-not $tokenHash -or $WaitSeconds -eq 0) {
        return 0
    }

    # The collector records the hash of the token it exchanged (never the token).
    $credential = Join-Path $data 'state\management-credential\credential.json'
    for ($second = 0; $second -lt $WaitSeconds; $second++) {
        if (Test-Path -LiteralPath $credential -PathType Leaf) {
            $text = [System.IO.File]::ReadAllText($credential)
            if ($text.Contains(('"consumedTokenSha256":"{0}"' -f $tokenHash))) {
                Write-Information 'Enrolled: the collector is Pending until an approver approves it in the console.' -InformationAction Continue
                return 0
            }
            if ($text.Contains(('"refusedTokenSha256":"{0}"' -f $tokenHash))) {
                Write-Error 'Management refused the enrolment token; create a new token and run again.' -ErrorAction Continue
                return 3
            }
        }
        Start-Sleep -Seconds 1
    }
    Write-Error "Enrolment not confirmed after $WaitSeconds s; the collector keeps retrying." -ErrorAction Continue
    return 4
}

# Dot-sourcing (tests) loads the functions only.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Install-BowerCollector @PSBoundParameters)
}
