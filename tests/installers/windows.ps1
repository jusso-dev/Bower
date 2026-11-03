<#
.SYNOPSIS
CI install test for the Windows MSI and offline installer (#112).

.DESCRIPTION
Needs the x64 offline bundle in -PackagesDirectory and a development-mode management
API on 127.0.0.1:4320. Runs Install-BowerCollector.ps1 under Windows PowerShell 5.1,
proves the collector joins Pending as NT SERVICE\Bower with locked-down folders, then
uninstalls with msiexec /x and proves no secret is left behind. Never prints a token.

With -UpgradeTestDirectory and -ExpectedVersion it then installs the older test MSI (the
same binaries as <core>-dev.0, ProductVersion MAJOR.MINOR.0), upgrades to this build,
checks every reported version, and proves that a downgrade is refused with a clear
message while the service, settings and queue stay untouched, that the same MSI
reinstalls as a no-op, and that BOWERALLOWDOWNGRADE=1 rolls back on purpose
(docs/operations/release-versioning.md).

.PARAMETER PackagesDirectory
Folder holding bower-collector-offline-<version>-win-x64.zip.

.PARAMETER UpgradeTestDirectory
Folder holding the older test MSI, bower-collector-<core>-dev.0-x64.msi.

.PARAMETER ExpectedVersion
The version this build reports, for example 0.1.0-dev.362.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackagesDirectory,
    [string] $UpgradeTestDirectory,
    [string] $ExpectedVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$base = 'http://127.0.0.1:4320'
$serviceSid = 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086'
$data = Join-Path $env:ProgramData 'Bower'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('bower-installer-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$tokens = [System.Collections.Generic.List[string]]::new()

function Assert-That([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
}

function Get-Status([string] $Id) {
    try { (Invoke-RestMethod -Uri "$base/api/collectors/$Id").status } catch { 'missing' }
}

function Assert-NoToken([string] $Path, [string] $What) {
    foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue) {
        # The running collector holds the queue open for writing.
        $stream = [System.IO.FileStream]::new($file.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        try { $text = [System.IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
        foreach ($token in $tokens) {
            Assert-That (-not $text.Contains($token)) "an enrolment token is in $What ($($file.Name))"
        }
    }
}

function Get-Rules([string] $Path) {
    (Get-Acl -LiteralPath $Path).Access | ForEach-Object {
        [pscustomobject]@{
            Sid    = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            Rights = $_.FileSystemRights
            Type   = $_.AccessControlType
        }
    }
}

function Assert-Folder([string] $Path, [string] $ServiceRights) {
    $acl = Get-Acl -LiteralPath $Path
    $rules = @(Get-Rules $Path)
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $serviceSid)
    foreach ($rule in $rules) {
        Assert-That ($allowed -contains $rule.Sid) "$Path grants access to $($rule.Sid)"
    }
    $service = @($rules | Where-Object Sid -EQ $serviceSid)
    Assert-That ($service.Count -ge 1) "$Path does not grant NT SERVICE\Bower access"
    foreach ($rule in $service) {
        Assert-That (($rule.Rights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions) -eq 0) "NT SERVICE\Bower can change permissions on $Path"
        Assert-That (($rule.Rights -band [System.Security.AccessControl.FileSystemRights]::TakeOwnership) -eq 0) "NT SERVICE\Bower can take ownership of $Path"
        if ($ServiceRights -eq 'Read') {
            Assert-That (($rule.Rights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -eq 0) "NT SERVICE\Bower can write to $Path"
        }
        else {
            Assert-That (($rule.Rights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify) "NT SERVICE\Bower cannot modify $Path"
        }
    }
    if ($Path -eq $data) {
        Assert-That $acl.AreAccessRulesProtected "$Path inherits the ProgramData ACL"
    }
}

function Invoke-Msi([string[]] $Arguments, [string] $Log) {
    $process = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList (
        $Arguments + @('/qn', '/norestart', '/l*v', ('"{0}"' -f (Join-Path $work $Log))))
    $process.ExitCode
}

function Wait-Healthy {
    for ($i = 0; $i -lt 60; $i++) {
        try { Invoke-RestMethod http://127.0.0.1:4319/health -TimeoutSec 2 | Out-Null; return } catch { Start-Sleep -Seconds 1 }
    }
    throw 'FAIL: collector never became healthy'
}

function Get-InstalledState {
    # Everything a refused downgrade must leave alone.
    $product = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'Bower Collector' })
    Assert-That ($product.Count -eq 1) "expected one installed Bower Collector, found $($product.Count)"
    [pscustomobject]@{
        DisplayVersion = $product[0].DisplayVersion
        Version        = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Bower\Collector').Version
        ProcessId      = (Get-CimInstance Win32_Service -Filter "Name='Bower'").ProcessId
        Settings       = (Get-FileHash -LiteralPath (Join-Path $data 'bower.env') -Algorithm SHA256).Hash
        Queue          = (Get-Item -LiteralPath (Join-Path $data 'state\queue.db')).CreationTimeUtc.Ticks
    } | ConvertTo-Json -Compress
}

function Test-Versioning([string] $Older, [string] $Newer, [string] $Version) {
    Assert-That ($Version -match '^(\d+)\.(\d+)\.\d+(-(dev|rc)\.\d+)?$') "-ExpectedVersion is not a Bower version: $Version"
    $msiPrefix = '^{0}\.{1}\.' -f $Matches[1], $Matches[2]
    $oldVersion = $Version.Split('-')[0] + '-dev.0'
    $headers = @{}
    $status = { (Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers $headers).version }

    Write-Information "== Windows: install $oldVersion, upgrade to $Version (MSI)" -InformationAction Continue
    Assert-That ((Invoke-Msi @('/i', ('"{0}"' -f $Older)) 'older-install.log') -eq 0) 'older MSI did not install'
    Assert-That ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Bower\Collector').Version -eq $oldVersion) 'older MSI did not record its version'
    # An ingest token so /v1/status answers, wired through the operator settings file.
    $token = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $tokens.Add($token)
    [System.IO.File]::WriteAllText((Join-Path $data 'secrets\ingest-token'), $token)
    Set-Content -LiteralPath (Join-Path $data 'bower.env') -Encoding ASCII -Value "BOWER_INGEST_TOKEN_FILE=$data\secrets\ingest-token"
    & icacls.exe (Join-Path $data 'bower.env') /setowner '*S-1-5-32-544' | Out-Null
    $headers['Authorization'] = "Bearer $token"
    Restart-Service -Name Bower
    Wait-Healthy

    Assert-That ((Invoke-Msi @('/i', ('"{0}"' -f $Newer)) 'upgrade.log') -eq 0) 'upgrade MSI failed'
    Wait-Healthy
    $installed = Get-InstalledState | ConvertFrom-Json
    Assert-That ($installed.Version -eq $Version) "registry records $($installed.Version), expected $Version"
    Assert-That ($installed.DisplayVersion -match ($msiPrefix + '[1-9]\d*$')) "ProductVersion $($installed.DisplayVersion) is not MAJOR.MINOR.BUILD"
    $cli = & (Join-Path $env:ProgramFiles 'Bower\bower.exe') --version
    Assert-That ($cli -eq "bower $Version") "bower --version printed $cli"
    $collector = & (Join-Path $env:ProgramFiles 'Bower\Bower.Collector.exe') --version
    Assert-That ($collector -eq "bower-collector $Version") "Bower.Collector --version printed $collector"
    Assert-That ((& $status) -eq $Version) "/v1/status reports $(& $status)"
    Write-Information "upgraded: ProductVersion $($installed.DisplayVersion); registry, CLI, collector and /v1/status report $Version" -InformationAction Continue

    Write-Information "== Windows: downgrade to $oldVersion must be refused" -InformationAction Continue
    $before = Get-InstalledState
    $code = Invoke-Msi @('/i', ('"{0}"' -f $Older)) 'downgrade.log'
    $log = Get-Content -LiteralPath (Join-Path $work 'downgrade.log') -Raw
    Assert-That ($code -eq 1603) "downgrade exited with $code, expected 1603"
    Assert-That ($log.Contains('A newer Bower Collector is already installed')) 'the msiexec log does not explain the refused downgrade'
    Assert-That ((Get-InstalledState) -eq $before) 'a refused downgrade changed the product, service, settings or queue'
    Assert-That ((& $status) -eq $Version) 'status changed after a refused downgrade'
    Write-Information "refused (exit 1603): $(($log -split "`r?`n" | Select-String -SimpleMatch 'A newer Bower Collector' | Select-Object -First 1).Line.Trim())" -InformationAction Continue

    Write-Information '== Windows: the same MSI again is a no-op' -InformationAction Continue
    Assert-That ((Invoke-Msi @('/i', ('"{0}"' -f $Newer)) 'reinstall.log') -eq 0) 'same-version reinstall failed'
    Assert-That ((Get-InstalledState) -eq $before) 'reinstalling the installed MSI changed the product, service, settings or queue'

    Write-Information '== Windows: explicit rollback with BOWERALLOWDOWNGRADE=1' -InformationAction Continue
    Assert-That ((Invoke-Msi @('/i', ('"{0}"' -f $Older), 'BOWERALLOWDOWNGRADE=1') 'rollback.log') -eq 0) 'rollback MSI failed'
    Wait-Healthy
    $rolledBack = Get-InstalledState | ConvertFrom-Json
    $original = $before | ConvertFrom-Json
    Assert-That ($rolledBack.Version -eq $oldVersion) "rollback recorded $($rolledBack.Version)"
    Assert-That ($rolledBack.Settings -eq $original.Settings) 'rollback changed bower.env'
    Assert-That ($rolledBack.Queue -eq $original.Queue) 'rollback replaced the queue'
    Assert-That (Test-Path -LiteralPath (Join-Path $data 'secrets\ingest-token')) 'rollback deleted a secret'
    # The test MSI carries this build's binaries, so the service still reports $Version.
    Assert-That ((& $status) -eq $Version) 'the rolled-back service is not answering'

    Assert-That ((Invoke-Msi @('/i', ('"{0}"' -f $Newer)) 'upgrade-again.log') -eq 0) 'upgrade after rollback failed'
    Wait-Healthy
    Assert-That (((Get-InstalledState | ConvertFrom-Json).Version) -eq $Version) 'upgrade after rollback did not record the version'
    Assert-That ((Invoke-Msi @('/x', ('"{0}"' -f $Newer)) 'versioning-uninstall.log') -eq 0) 'uninstall after the versioning test failed'
    Assert-NoToken $work 'the installer logs'
    Write-Information "Windows versioning test passed: upgrade, refused downgrade, no-op reinstall, explicit rollback." -InformationAction Continue
}

try {
    $zip = @(Get-ChildItem -LiteralPath $PackagesDirectory -Filter 'bower-collector-offline-*-win-x64.zip' -File)
    Assert-That ($zip.Count -eq 1) 'expected one x64 offline bundle'
    Expand-Archive -LiteralPath $zip[0].FullName -DestinationPath $work
    $bundle = (Get-ChildItem -LiteralPath $work -Directory | Select-Object -First 1).FullName
    $seed = Join-Path $bundle 'seed'

    $body = @{ environment = 'ci'; collectorId = 'windows-offline'; reason = 'CI installer test'; expiresInHours = 1 } | ConvertTo-Json
    $token = (Invoke-RestMethod -Method Post -Uri "$base/api/enrolment-tokens" -ContentType 'application/json' -Body $body).token
    $tokens.Add($token)
    [System.IO.File]::WriteAllText((Join-Path $seed 'enrolment-token'), $token)
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    [System.IO.File]::WriteAllText((Join-Path $seed 'pack-trusted.pem'), $key.ExportSubjectPublicKeyInfoPem())

    Write-Information '== Windows: offline installer (MSI) under Windows PowerShell 5.1' -InformationAction Continue
    $installLog = Join-Path $work 'install.log'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $bundle 'Install-BowerCollector.ps1') `
        -ManagementEndpoint "$base/" -CollectorId windows-offline -Environment ci -WaitSeconds 120 -LogPath $installLog
    Assert-That ($LASTEXITCODE -eq 0) "Install-BowerCollector.ps1 exited with $LASTEXITCODE"
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $seed 'enrolment-token'))) 'seed token left in the bundle'

    $status = 'missing'
    for ($i = 0; $i -lt 60 -and $status -ne 'Pending'; $i++) {
        $status = Get-Status 'windows-offline'
        if ($status -ne 'Pending') { Start-Sleep -Seconds 2 }
    }
    Assert-That ($status -eq 'Pending') "windows-offline never joined Pending (last: $status)"
    Write-Information 'windows-offline joined Pending' -InformationAction Continue

    $service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
    Assert-That ($service.StartName -eq 'NT SERVICE\Bower') "service runs as $($service.StartName)"
    Assert-That ($service.StartMode -eq 'Auto') "service start mode is $($service.StartMode)"
    $serviceConfiguration = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
    $delayedStart = $serviceConfiguration.PSObject.Properties['DelayedAutoStart']
    Assert-That ($null -eq $delayedStart -or $delayedStart.Value -eq 0) 'service must start automatically without the delayed-start interval'
    Assert-That ($service.State -eq 'Running') "service is $($service.State)"
    $recovery = & sc.exe qfailure Bower | Out-String
    Assert-That ($LASTEXITCODE -eq 0) 'cannot read service recovery settings'
    # sc.exe annotates the reset period with its units before the colon.
    Assert-That ($recovery -match 'RESET_PERIOD\s+(?:\(in seconds\)\s*)?:\s*86400\b') 'service recovery does not reset after one day'
    Assert-That ([regex]::Matches($recovery, 'RESTART\s+--\s+Delay = 5000\b').Count -eq 3) 'service recovery must restart after five seconds for all three actions'
    Assert-That ((& sc.exe showsid Bower | Out-String).Contains($serviceSid)) 'service SID differs from the one in Bower.wxs'
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
    Assert-That ("$($owner.Domain)\$($owner.User)" -eq 'NT SERVICE\Bower') "collector process runs as $($owner.Domain)\$($owner.User)"

    $owner = (Get-Acl -LiteralPath $data).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    Assert-That (@('S-1-5-18', 'S-1-5-32-544') -contains $owner) "%ProgramData%\Bower is owned by $owner"
    Assert-Folder $data 'Read'
    Assert-Folder (Join-Path $data 'secrets') 'Read'
    Assert-Folder (Join-Path $data 'keys') 'Read'
    Assert-Folder (Join-Path $data 'policies') 'Read'
    Assert-Folder (Join-Path $data 'state') 'Modify'
    Assert-Folder (Join-Path $data 'enrolment') 'Modify'
    Assert-Folder (Join-Path $data 'state\management-credential') 'Modify'
    foreach ($item in Get-ChildItem -LiteralPath $data -Recurse -Force) {
        foreach ($rule in Get-Rules $item.FullName) {
            Assert-That (@('S-1-5-18', 'S-1-5-32-544', $serviceSid) -contains $rule.Sid) "$($item.FullName) grants access to $($rule.Sid)"
        }
    }

    $environment = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment
    Assert-That ($environment -contains 'BOWER_MANAGEMENT_AUTH=enrolment') 'enrolment mode not configured'
    Assert-That ($environment -contains 'BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE=true') 'token removal not configured'
    Assert-That ($environment -contains "BOWER_PACK_TRUSTED_KEYS=$data\keys\pack-trusted.pem") 'trusted pack key not configured'
    Assert-That (Test-Path -LiteralPath (Join-Path $data 'keys\pack-trusted.pem')) 'trusted pack key not installed'
    Assert-That (Test-Path -LiteralPath (Join-Path $data 'state\management-credential\credential.json')) 'no management credential'
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $data 'enrolment\enrolment-token'))) 'enrolment token left on disk'
    Assert-NoToken $data '%ProgramData%\Bower'
    Assert-NoToken $work 'the installer logs'

    # Operator settings outside the MSI-owned service environment (BOWER_SETTINGS_FILE): the
    # collector must apply them, and upgrade/repair cannot rewrite them. Prove the effect:
    # an invalid value stops startup, then a valid listener moves /health to another port.
    Assert-That ($environment -contains "BOWER_SETTINGS_FILE=$data\bower.env") 'settings file not configured'
    function Test-Health([int] $port) {
        try { Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 2 | Out-Null; $true } catch { $false }
    }
    function Write-SettingsFile([string] $content) {
        Set-Content -LiteralPath (Join-Path $data 'bower.env') -Value $content -Encoding ASCII
        # Elevated admins on client Windows own new files themselves; the collector requires
        # SYSTEM or Administrators, as documented.
        & icacls.exe (Join-Path $data 'bower.env') /setowner '*S-1-5-32-544' | Out-Null
    }
    Write-SettingsFile 'BOWER_OUTPUT=not-a-real-output'
    Stop-Service -Name Bower
    Start-Service -Name Bower -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 8
    Assert-That (-not (Test-Health 4319)) 'collector ignored an invalid value in bower.env'
    Write-SettingsFile 'BOWER_LISTEN_URL=http://127.0.0.1:4329'
    Stop-Service -Name Bower -ErrorAction SilentlyContinue
    Start-Service -Name Bower
    $applied = $false
    for ($attempt = 0; $attempt -lt 30 -and -not $applied; $attempt++) { Start-Sleep -Seconds 1; $applied = Test-Health 4329 }
    Assert-That $applied 'collector did not apply BOWER_LISTEN_URL from bower.env'
    Assert-That (-not (Test-Health 4319)) 'bower.env did not override the service environment'

    # An operator secret file; uninstall must remove it too.
    Set-Content -LiteralPath (Join-Path $data 'secrets\ingest-token') -Value 'placeholder'

    Write-Information '== Windows: msiexec /x' -InformationAction Continue
    $msi = (Get-ChildItem -LiteralPath $bundle -Filter 'bower-collector-*.msi' -File).FullName
    $uninstall = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @(
        '/x', ('"{0}"' -f $msi), '/qn', '/norestart', '/l*v', ('"{0}"' -f (Join-Path $work 'uninstall.log')))
    Assert-That ($uninstall.ExitCode -eq 0) "msiexec /x exited with $($uninstall.ExitCode)"
    Assert-That ($null -eq (Get-Service -Name Bower -ErrorAction SilentlyContinue)) 'service left behind'
    foreach ($path in 'state\management-credential', 'enrolment', 'secrets', 'bower.env') {
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $data $path))) "$path left behind after uninstall"
    }
    Assert-That (Test-Path -LiteralPath (Join-Path $data 'state\queue.db')) 'queue deleted on uninstall'
    Assert-That (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Bower\Collector')) 'remembered settings left behind'
    Assert-NoToken $work 'the installer logs'
    Write-Information 'Windows installer test passed: Pending as NT SERVICE\Bower, no secret left after uninstall.' -InformationAction Continue

    if ($UpgradeTestDirectory) {
        Test-Versioning -Older (Get-ChildItem -LiteralPath $UpgradeTestDirectory -Filter 'bower-collector-*-x64.msi' -File).FullName `
            -Newer $msi -Version $ExpectedVersion
    }
}
finally {
    # msiexec logs hold no secret values (asserted above); keep them for a failed run.
    if ($env:RUNNER_TEMP) {
        Get-ChildItem -LiteralPath $work -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Copy-Item -Destination $env:RUNNER_TEMP -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
