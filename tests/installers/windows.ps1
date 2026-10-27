<#
.SYNOPSIS
CI install test for the Windows MSI and offline installer (#112).

.DESCRIPTION
Needs the x64 offline bundle in -PackagesDirectory and a development-mode management
API on 127.0.0.1:4320. Runs Install-BowerCollector.ps1 under Windows PowerShell 5.1,
proves the collector joins Pending as NT SERVICE\Bower with locked-down folders, then
uninstalls with msiexec /x and proves no secret is left behind. Never prints a token.

.PARAMETER PackagesDirectory
Folder holding bower-collector-offline-<version>-win-x64.zip.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackagesDirectory
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
    Assert-That ($service.State -eq 'Running') "service is $($service.State)"
    $recovery = & sc.exe qfailure Bower | Out-String
    Assert-That ($LASTEXITCODE -eq 0) 'cannot read service recovery settings'
    Assert-That ($recovery -match 'RESET_PERIOD\s+:\s+86400') 'service recovery does not reset after one day'
    Assert-That ([regex]::Matches($recovery, 'RESTART\s+--\s+Delay = 5000').Count -eq 3) 'service recovery must restart after five seconds for all three actions'
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

    # An operator secret file; uninstall must remove it too.
    Set-Content -LiteralPath (Join-Path $data 'secrets\ingest-token') -Value 'placeholder'

    Write-Information '== Windows: msiexec /x' -InformationAction Continue
    $msi = (Get-ChildItem -LiteralPath $bundle -Filter 'bower-collector-*.msi' -File).FullName
    $uninstall = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @(
        '/x', ('"{0}"' -f $msi), '/qn', '/norestart', '/l*v', ('"{0}"' -f (Join-Path $work 'uninstall.log')))
    Assert-That ($uninstall.ExitCode -eq 0) "msiexec /x exited with $($uninstall.ExitCode)"
    Assert-That ($null -eq (Get-Service -Name Bower -ErrorAction SilentlyContinue)) 'service left behind'
    foreach ($path in 'state\management-credential', 'enrolment', 'secrets') {
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $data $path))) "$path left behind after uninstall"
    }
    Assert-That (Test-Path -LiteralPath (Join-Path $data 'state\queue.db')) 'queue deleted on uninstall'
    Assert-That (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Bower\Collector')) 'remembered settings left behind'
    Assert-NoToken $work 'the installer logs'
    Write-Information 'Windows installer test passed: Pending as NT SERVICE\Bower, no secret left after uninstall.' -InformationAction Continue
}
finally {
    # msiexec logs hold no secret values (asserted above); keep them for a failed run.
    if ($env:RUNNER_TEMP) {
        Get-ChildItem -LiteralPath $work -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Copy-Item -Destination $env:RUNNER_TEMP -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
