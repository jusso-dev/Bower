$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    if ($env:BOWER_LAB_HOST -notin @('Wec','Windows1','Windows2')) { throw 'Wrong host platform' }
    Import-Module AWSPowerShell -ErrorAction Stop
    $root = Join-Path $env:ProgramData 'BowerLab'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Lab ACL setup failed' }
    $manifestFile = Join-Path $root 'manifest.json'
    Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key 'artifacts/manifest.json' -File $manifestFile -Region $env:AWS_DEFAULT_REGION | Out-Null
    $manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
    $identity = Get-STSCallerIdentity -Region $env:AWS_DEFAULT_REGION
    if ($identity.Account -ne $manifest.account -or $manifest.runId -ne $env:BOWER_LAB_RUN) { throw 'Lab identity mismatch' }
    $msi = Join-Path $root 'collector.msi'
    Read-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key 'artifacts/collector.msi' -File $msi -Region $env:AWS_DEFAULT_REGION | Out-Null
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.files.'collector.msi') { throw 'Package checksum mismatch' }
    $management = 'https://' + $manifest.hosts.Control.ip + '/'
    $collectorId = $env:BOWER_LAB_RUN + '-' + $env:BOWER_LAB_HOST.ToLowerInvariant()
    $install = Start-Process msiexec.exe -ArgumentList @('/i',('"'+$msi+'"'),'/qn','/norestart',('MANAGEMENTENDPOINT='+$management),('COLLECTORID='+$collectorId),'BOWERENVIRONMENT=lab') -Wait -PassThru
    if ($install.ExitCode -notin @(0,3010)) { throw 'MSI installation failed' }
    Stop-Service Bower -ErrorAction SilentlyContinue
    $data = Join-Path $env:ProgramData 'Bower'
    $bundle = (Get-SECSecretValue -SecretId ('bower-lab/'+$env:BOWER_LAB_RUN+'/'+$env:BOWER_LAB_HOST) -Region $env:AWS_DEFAULT_REGION).SecretString | ConvertFrom-Json
    foreach ($folder in @('secrets','keys','packs','enrolment','state')) { New-Item -ItemType Directory -Path (Join-Path $data $folder) -Force | Out-Null }
    [IO.File]::WriteAllText((Join-Path $data 'keys\ca.pem'),$bundle.ca)
    [IO.File]::WriteAllText((Join-Path $data 'keys\pack.pub.pem'),$bundle.packPublicKey)
    [IO.File]::WriteAllText((Join-Path $data 'secrets\client.key'),$bundle.key)
    [IO.File]::WriteAllText((Join-Path $data 'secrets\client.crt'),$bundle.certificate)
    [IO.File]::WriteAllBytes((Join-Path $data 'secrets\privacy.key'),[Convert]::FromBase64String($bundle.privacyKey))
    [IO.File]::WriteAllBytes((Join-Path $data 'packs\windows-lab.bowerpack'),[Convert]::FromBase64String($bundle.pack))
    if (-not (Test-Path (Join-Path $data 'state\management-credential\credential.json'))) {
        [IO.File]::WriteAllText((Join-Path $data 'enrolment\enrolment-token'),$bundle.enrolmentToken)
    }
    $bundle = $null
    if (-not [Diagnostics.EventLog]::SourceExists('BowerLab')) { [Diagnostics.EventLog]::CreateEventSource('BowerLab','Application') }
    $sid = (New-Object Security.Principal.NTAccount('NT SERVICE\Bower')).Translate([Security.Principal.SecurityIdentifier]).Value
    if (-not (Get-LocalGroupMember -Group 'Event Log Readers' | Where-Object { $_.SID.Value -eq $sid })) {
        Add-LocalGroupMember -Group 'Event Log Readers' -Member 'NT SERVICE\Bower'
    }
    $source = @{apiVersion='bower.security/v1';kind='WindowsEventLogSource';subscriptions=@(@{
        id='lab-application';channel='Application';eventIds=@(9010);providers=@('BowerLab');pack='windows-lab';parser=0;readExisting=$true
    })}
    [IO.File]::WriteAllText((Join-Path $data 'windows-source.json'),($source | ConvertTo-Json -Depth 8))
    $scopes = @(@{producer='anonymous';application=@{name='BowerLab';environment='lab'};source=@{ipAddress='192.0.2.10'}})
    [IO.File]::WriteAllText((Join-Path $data 'producer-scopes.json'),(ConvertTo-Json -InputObject $scopes -Depth 5))
    $settings = @{
        BOWER_LISTEN_URL='http://127.0.0.1:4319';BOWER_OUTPUT='relay';BOWER_ENVIRONMENT='lab';BOWER_COLLECTOR_ID=$collectorId
        BOWER_MANAGEMENT_ENDPOINT=$management;BOWER_MANAGEMENT_AUTH='enrolment';BOWER_MANAGEMENT_CA_BUNDLE=(Join-Path $data 'keys\ca.pem')
        BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE=(Join-Path $data 'enrolment\enrolment-token');BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE='true'
        BOWER_RELAY_URL=('https://'+$manifest.hosts.Collector.ip+':4319');BOWER_RELAY_CA_BUNDLE=(Join-Path $data 'keys\ca.pem')
        BOWER_RELAY_CLIENT_CERTIFICATE_FILE=(Join-Path $data 'secrets\client.crt');BOWER_RELAY_CLIENT_KEY_FILE=(Join-Path $data 'secrets\client.key')
        BOWER_PRIVACY_HMAC_KEY_FILE=(Join-Path $data 'secrets\privacy.key');BOWER_QUEUE_MAX_BYTES='1073741824';BOWER_INGEST_RATE_PER_SECOND='6000'
        BOWER_PACKS=(Join-Path $data 'packs\windows-lab.bowerpack');BOWER_PACK_TRUSTED_KEYS=(Join-Path $data 'keys\pack.pub.pem')
        BOWER_WINDOWS_EVENTLOG_CONFIG=(Join-Path $data 'windows-source.json');BOWER_PRODUCER_SCOPES_FILE=(Join-Path $data 'producer-scopes.json')
    }
    $registry='HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
    $existing=@((Get-ItemProperty -Path $registry -Name Environment).Environment | Where-Object { -not $settings.ContainsKey(($_ -split '=',2)[0]) })
    $environment=@($existing)+@($settings.GetEnumerator() | ForEach-Object { $_.Key+'='+$_.Value })
    New-ItemProperty -Path $registry -Name Environment -Value $environment -PropertyType MultiString -Force | Out-Null
    Start-Service Bower
    $healthy=$false
    for ($attempt=0;$attempt -lt 60;$attempt++) {
        try { $null=Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 3; $healthy=$true; break } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $healthy) { throw 'Collector health failed' }
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{phase='install';host=$env:BOWER_LAB_HOST;status='passed';packageSha256=$manifest.files.'collector.msi';signedPackage=$false;serviceAccount=(Get-CimInstance Win32_Service -Filter "Name='Bower'").StartName;usedMemoryPercent=[math]::Round((1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,1)} | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{phase='install';host=$env:BOWER_LAB_HOST;status='failed';errorType=$_.Exception.GetType().Name;line=$_.InvocationInfo.ScriptLineNumber} | ConvertTo-Json -Compress
    exit 1
}
