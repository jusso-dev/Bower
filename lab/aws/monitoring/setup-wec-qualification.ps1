# Fresh, owned Windows lab hosts only. Invoke through monitoring/run.py.
# Native errors are deliberately suppressed: downloaded material includes credentials.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Get-WecSafeFailure($Failure) {
    # FullyQualifiedErrorId can itself contain a thrown message. Never expose it
    # or Exception.Message unless it exactly matches a reviewed static value.
    $codes = @('manifest-identity', 'manifest-fields', 'manifest-files', 'manifest-name', 'manifest-entry',
        'destination-fields', 'destination-values', 'archive-count', 'archive-name', 'archive-link',
        'archive-size', 'archive-executable', 'archive-parent-file', 'archive-expanded-bound',
        'archive-expanded-length', 'native-command-failed', 'artifact-size', 'public-preflight',
        'fresh-host-required', 'aws-cli-required', 'aws-account', 'manifest-hash', 'artifact-hash',
        'synthetic-account-exists', 'subscription-exists', 'channel-read', 'channel-acl',
        'collector-not-ready', 'health-task-exists')
    $knownIds = @('NativeCommandError', 'CommandNotFoundException', 'PropertyNotFoundStrict',
        'VariableIsUndefined', 'MethodInvocationException', 'ConstructorInvokedThrowException',
        'PositionalParameterNotFound', 'NamedParameterNotFound', 'AmbiguousParameterSet',
        'ParameterBindingException', 'CannotConvertArgument', 'CannotConvertArgumentNoMessage',
        'ParameterArgumentValidationError', 'ParameterArgumentValidationErrorEmptyStringNotAllowed',
        'PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',
        'PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand',
        'NoServiceFoundForGivenName,Microsoft.PowerShell.Commands.GetServiceCommand',
        'UnauthorizedAccess,Microsoft.PowerShell.Commands.NewItemCommand',
        'System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.SetAclCommand')
    $code = if ($codes -ccontains $Failure.Exception.Message) { $Failure.Exception.Message } else { 'unclassified' }
    $fqid = if (($knownIds + $codes) -ccontains $Failure.FullyQualifiedErrorId) { $Failure.FullyQualifiedErrorId } else { 'redacted-unrecognized' }
    $line = if ($Failure.InvocationInfo) { [int]$Failure.InvocationInfo.ScriptLineNumber } else { 0 }
    return @{ exceptionType = $Failure.Exception.GetType().FullName;
        category = $Failure.CategoryInfo.Category.ToString(); fullyQualifiedErrorId = $fqid;
        staticCode = $code; scriptLine = $line }
}

function Assert-WecManifest($Manifest, [string]$RunId) {
    $limits = @{
        'collector.zip' = 536870912; 'sentinel.json' = 65536
        'ingest.pem' = 65536; 'ingest-token' = 4096; 'hmac.key' = 4096
        'windows-security-logon-1.0.2.bowerpack' = 16777216
        'pack-signing.pub.pem' = 65536; 'collector-health.yaml' = 65536
        'Test-BowerCollectorHealth.ps1' = 1048576
    }
    if ($Manifest.schemaVersion -ne 1 -or $Manifest.runId -cne $RunId -or $Manifest.role -cne 'windows') { throw 'manifest-identity' }
    if (@($Manifest.PSObject.Properties.Name | Sort-Object) -join ',' -cne 'files,role,runId,schemaVersion') { throw 'manifest-fields' }
    $names = @($Manifest.files.PSObject.Properties.Name)
    if ($names.Count -ne $limits.Count) { throw 'manifest-files' }
    foreach ($name in $names) {
        if (-not ($limits.Keys -ccontains $name)) { throw 'manifest-name' }
        $item = $Manifest.files.$name
        if ((@($item.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'bytes,sha256' -or
            $item.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            ($item.bytes -isnot [long] -and $item.bytes -isnot [int]) -or
            $item.bytes -lt 1 -or $item.bytes -gt $limits[$name]) { throw 'manifest-entry' }
    }
    return $limits
}

function Read-WecDestination($Settings) {
    if ((@($Settings.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'client,dce,dcr,tenant') { throw 'destination-fields' }
    if ($Settings.tenant -cne 'f4f33fb1-b681-40d1-a854-6f888d45b891' -or
        $Settings.client -notmatch '^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$' -or
        $Settings.dcr -cnotmatch '^dcr-[a-f0-9]{32}$' -or
        $Settings.dce -cnotmatch '^https://[a-z0-9.-]+\.ingest\.monitor\.azure\.com/?$') { throw 'destination-values' }
    return @(
        'BOWER_OUTPUT=azure-logs-ingestion', 'BOWER_AZURE_CREDENTIAL=environment',
        'BOWER_STREAM_NAME=Custom-BowerSecurity', "BOWER_DCE_ENDPOINT=$($Settings.dce)",
        "BOWER_DCR_ID=$($Settings.dcr)", "AZURE_TENANT_ID=$($Settings.tenant)",
        "AZURE_CLIENT_ID=$($Settings.client)",
        'AZURE_CLIENT_CERTIFICATE_PATH=C:\ProgramData\Bower\secrets\ingest.pem'
    )
}

function Assert-WecArchive([string]$Path) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -lt 1 -or $archive.Entries.Count -gt 4096) { throw 'archive-count' }
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        [long]$total = 0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            # Conservative portable names also reject Windows ADS, reserved devices and aliases.
            if ($name -cnotmatch '^collector/([A-Za-z0-9_-][A-Za-z0-9_.-]*/?)*$' -or
                $name -match '(^|/)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|/|$)' -or
                $name -match '\.(/|$)' -or -not $names.Add($name.TrimEnd('/'))) { throw 'archive-name' }
            $mode = ($entry.ExternalAttributes -shr 16) -band 61440
            if ($mode -notin @(0, 16384, 32768) -or ($entry.ExternalAttributes -band 1024)) { throw 'archive-link' }
            $total += $entry.Length
            if ($entry.Length -gt 1073741824 -or $total -gt 1073741824 -or ($name.EndsWith('/') -and $entry.Length -ne 0)) { throw 'archive-size' }
        }
        if (-not ($archive.Entries | Where-Object { $_.FullName -ceq 'collector/Bower.Collector.exe' -and $_.Length -gt 0 })) { throw 'archive-executable' }
        foreach ($entry in $archive.Entries) {
            $parts = $entry.FullName.TrimEnd('/').Split('/')
            for ($index = 1; $index -lt $parts.Count; $index++) {
                $ancestor = ($parts[0..($index - 1)] -join '/')
                $file = $archive.Entries | Where-Object { $_.FullName -ieq $ancestor }
                if ($file) { throw 'archive-parent-file' }
            }
        }
    } finally { $archive.Dispose() }
}

function Set-WecPrivateDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create private owned lab directory')) { return }
    New-Item -ItemType Directory -Path $Path | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = New-Object Security.Principal.SecurityIdentifier($identity)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Expand-WecArchive([string]$Path, [string]$Destination) {
    # Validate before creating anything, then bound actual decompression as well as
    # advertised entry lengths (a hostile ZIP can lie in its central directory).
    Assert-WecArchive $Path
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    [long]$total = 0
    $buffer = New-Object byte[] 65536
    try {
        foreach ($entry in $archive.Entries) {
            $target = Join-Path $Destination $entry.FullName
            if ($entry.FullName.EndsWith('/')) { New-Item -ItemType Directory -Path $target -Force | Out-Null; continue }
            New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
            $inputStream = $entry.Open()
            $outputStream = $null
            try {
                $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                [long]$written = 0
                while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $count; $total += $count
                    if ($written -gt $entry.Length -or $total -gt 1073741824) { throw 'archive-expanded-bound' }
                    $outputStream.Write($buffer, 0, $count)
                }
                if ($written -ne $entry.Length) { throw 'archive-expanded-length' }
            } finally { if ($outputStream) { $outputStream.Dispose() }; $inputStream.Dispose() }
        }
    } finally { $archive.Dispose() }
}

function Invoke-WecNative([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'native-command-failed' }
}

function Receive-WecArtifact([string]$Name, [long]$Maximum, [long]$Expected = -1) {
    $key = "artifacts/qualification/$($env:BOWER_LAB_RUN)/windows/$Name"
    $sizeText = & $aws s3api head-object --bucket $env:BOWER_LAB_BUCKET --key $key --query ContentLength --output text 2>$null
    [long]$size = 0
    if ($LASTEXITCODE -ne 0 -or -not [long]::TryParse([string]$sizeText, [ref]$size) -or
        $size -lt 1 -or $size -gt $Maximum -or ($Expected -ge 0 -and $size -ne $Expected)) { throw 'artifact-size' }
    Invoke-WecNative $aws @('s3', 'cp', "$prefix/$Name", "$stage\$Name", '--only-show-errors')
}

$stage = $null
$createdService = $false
$step = 'preflight'
try {
    if ($env:OS -ne 'Windows_NT' -or $env:BOWER_LAB_RUN -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or
        $env:BOWER_LAB_BUCKET -cnotmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or
        $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2' -or
        $env:BOWER_ARTIFACT_MANIFEST_SHA256 -cnotmatch '^[a-f0-9]{64}$') { throw 'public-preflight' }
    $install = 'C:\Program Files\Bower'
    $data = 'C:\ProgramData\Bower'
    if ((Test-Path $install) -or (Test-Path $data) -or (Get-Service Bower -ErrorAction SilentlyContinue)) { throw 'fresh-host-required' }
    $aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
    if (-not (Test-Path $aws)) { throw 'aws-cli-required' }
    $account = & $aws sts get-caller-identity --query Account --output text 2>$null
    if ($LASTEXITCODE -ne 0 -or $account -ne '959038055523') { throw 'aws-account' }
    # run.py checks exact instance ID/role/run tags before dispatch. Host role deliberately
    # has no EC2 DescribeInstances permission; do not weaken that role for this installer.
    $stage = Join-Path 'C:\ProgramData' ('BowerStage-' + [Guid]::NewGuid().ToString('N'))
    Set-WecPrivateDirectory $stage
    $prefix = "s3://$($env:BOWER_LAB_BUCKET)/artifacts/qualification/$($env:BOWER_LAB_RUN)/windows"
    $step = 'artifacts'
    Receive-WecArtifact 'manifest.json' 65536
    if ((Get-Item "$stage\manifest.json").Length -gt 65536 -or
        (Get-FileHash "$stage\manifest.json").Hash.ToLowerInvariant() -cne $env:BOWER_ARTIFACT_MANIFEST_SHA256) { throw 'manifest-hash' }
    $manifest = Get-Content "$stage\manifest.json" -Raw | ConvertFrom-Json
    $limits = Assert-WecManifest $manifest $env:BOWER_LAB_RUN
    foreach ($name in $limits.Keys) {
        Receive-WecArtifact $name $limits[$name] $manifest.files.$name.bytes
        $file = Get-Item -LiteralPath "$stage\$name"
        if ($file.Length -ne $manifest.files.$name.bytes -or
            (Get-FileHash $file.FullName).Hash.ToLowerInvariant() -cne $manifest.files.$name.sha256) { throw 'artifact-hash' }
    }
    $destination = Read-WecDestination (Get-Content "$stage\sentinel.json" -Raw | ConvertFrom-Json)
    Assert-WecArchive "$stage\collector.zip"
    $step = 'install'
    Expand-WecArchive "$stage\collector.zip" "$stage\expanded"
    Set-WecPrivateDirectory $install
    Copy-Item "$stage\expanded\collector\*" $install -Recurse
    Set-WecPrivateDirectory $data
    foreach ($folder in 'data', 'secrets', 'packs', 'keys', 'policies', 'monitoring') {
        New-Item -ItemType Directory -Path "$data\$folder" | Out-Null
    }
    foreach ($name in 'ingest.pem', 'ingest-token', 'hmac.key') { Copy-Item "$stage\$name" "$data\secrets\$name" }
    Copy-Item "$stage\windows-security-logon-1.0.2.bowerpack" "$data\packs\"
    Copy-Item "$stage\pack-signing.pub.pem" "$data\keys\"
    Copy-Item "$stage\collector-health.yaml" "$data\policies\"
    Copy-Item "$stage\Test-BowerCollectorHealth.ps1" "$data\monitoring\"
    # Deterministic 20-character nonexistent account, scoped to this run.
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $accountName = 'bwr' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($env:BOWER_LAB_RUN))).Replace('-', '').ToLowerInvariant()).Substring(0, 17) } finally { $hash.Dispose() }
    if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) { throw 'synthetic-account-exists' }
    $subscriptionName = 'bower-' + $accountName
    if ((& wecutil.exe es) -contains $subscriptionName) { throw 'subscription-exists' }
    $source = @{ apiVersion = 'bower.security/v1'; kind = 'WindowsEventLogSource'; subscriptions = @(@{
        id = 'wec-security'; channel = 'ForwardedEvents'; eventIds = @(4625)
        providers = @('Microsoft-Windows-Security-Auditing'); pack = 'windows-security-logon'; parser = 0
        readExisting = $false; pollIntervalSeconds = 1; batchSize = 256
    }) }
    $source | ConvertTo-Json -Depth 6 | Set-Content "$data\windows-eventlog.json" -Encoding UTF8
    $step = 'service'
    Invoke-WecNative sc.exe @('create', 'Bower', 'binPath=', "$install\Bower.Collector.exe", 'start=', 'auto', 'obj=', 'NT SERVICE\Bower')
    $createdService = $true
    $registry = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
    Set-ItemProperty $registry ImagePath -Type ExpandString -Value "`"$install\Bower.Collector.exe`""
    Invoke-WecNative sc.exe @('failure', 'Bower', 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/5000')
    Invoke-WecNative sc.exe @('failureflag', 'Bower', '1')
    $sid = (New-Object Security.Principal.NTAccount('NT SERVICE\Bower')).Translate([Security.Principal.SecurityIdentifier]).Value
    foreach ($path in $install, $data) { Invoke-WecNative icacls.exe @($path, '/grant', "*${sid}:(OI)(CI)RX", '/Q') }
    Invoke-WecNative icacls.exe @("$data\data", '/grant', "*${sid}:(OI)(CI)M", '/Q')
    # Only SYSTEM/admin may modify binaries/config/secrets; service can write queue only.
    $environment = $destination + @(
        'BOWER_LISTEN_URL=http://127.0.0.1:4319', "BOWER_QUEUE_PATH=$data\data\bower.db",
        "BOWER_POLICY_DIRECTORY=$data\policies", "BOWER_COLLECTOR_ID=$($env:BOWER_LAB_RUN)-windows",
        'BOWER_ENVIRONMENT=lab', "BOWER_INGEST_TOKEN_FILE=$data\secrets\ingest-token",
        "BOWER_PRIVACY_HMAC_KEY_FILE=$data\secrets\hmac.key", "BOWER_PACK_TRUSTED_KEYS=$data\keys\pack-signing.pub.pem",
        "BOWER_PACKS=$data\packs\windows-security-logon-1.0.2.bowerpack",
        "BOWER_WINDOWS_EVENTLOG_CONFIG=$data\windows-eventlog.json", 'BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60',
        'BOWER_DELIVERY_LEASE_SECONDS=90', 'BOWER_DELIVERY_TIMEOUT_SECONDS=60',
        'BOWER_QUEUE_MAX_BYTES=1073741824', 'BOWER_QUEUE_RETENTION_HOURS=24'
    )
    Set-ItemProperty $registry Environment -Type MultiString -Value $environment
    if (-not [Diagnostics.EventLog]::SourceExists('Bower.Collector')) { New-EventLog -LogName Application -Source 'Bower.Collector' }
    $step = 'wec'
    Invoke-WecNative winrm.cmd @('quickconfig', '-quiet')
    # No remote WinRM ingress: only the local collector-initiated subscription is used.
    Get-NetFirewallRule -Name 'WINRM*' -ErrorAction Stop | Disable-NetFirewallRule
    Invoke-WecNative wecutil.exe @('qc', '/q')
    $readers = Get-LocalGroup -SID 'S-1-5-32-573'
    $networkService = (New-Object Security.Principal.SecurityIdentifier('S-1-5-20')).Translate([Security.Principal.NTAccount]).Value
    if (-not (Get-LocalGroupMember -Group $readers | Where-Object { $_.SID.Value -eq 'S-1-5-20' })) { Add-LocalGroupMember -Group $readers -Member $networkService }
    Restart-Service WinRM -Force
    Restart-Service Wecsvc -Force
    Invoke-WecNative wevtutil.exe @('sl', 'ForwardedEvents', '/ms:1073741824')
    Invoke-WecNative wevtutil.exe @('sl', 'Security', '/ms:1073741824')
    [xml]$channel = & wevtutil.exe gl ForwardedEvents /f:xml
    if ($LASTEXITCODE -ne 0) { throw 'channel-read' }
    $sddl = [string]$channel.channel.channelAccess
    if (-not $sddl) { throw 'channel-acl' }
    Invoke-WecNative wevtutil.exe @('sl', 'ForwardedEvents', "/ca:$sddl(A;;0x1;;;$sid)")
    $subscription = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>$subscriptionName</SubscriptionId><SubscriptionType>CollectorInitiated</SubscriptionType>
  <Description>Owned synthetic Bower qualification $($env:BOWER_LAB_RUN)</Description><Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri><ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Pull"><Batching><MaxItems>256</MaxItems><MaxLatencyTime>1000</MaxLatencyTime></Batching><PushSettings><Heartbeat Interval="60000"/></PushSettings></Delivery>
  <Query><![CDATA[<QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4625)] and EventData[Data[@Name='TargetUserName']='$accountName']]</Select></Query></QueryList>]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents><TransportName>HTTP</TransportName><ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/><LogFile>ForwardedEvents</LogFile><CredentialsType>Default</CredentialsType>
  <EventSources><EventSource Enabled="true"><Address>localhost</Address></EventSource></EventSources>
</Subscription>
"@
    $subscription | Set-Content "$data\monitoring\subscription.xml" -Encoding UTF8
    Invoke-WecNative wecutil.exe @('cs', "$data\monitoring\subscription.xml")
    Invoke-WecNative auditpol.exe @('/set', '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}', '/failure:enable')
    @{ runId = $env:BOWER_LAB_RUN; accountName = $accountName; subscription = $subscriptionName; manifestSha256 = $env:BOWER_ARTIFACT_MANIFEST_SHA256 } |
        ConvertTo-Json | Set-Content "$data\monitoring\qualification.json" -Encoding UTF8
    $step = 'start'
    Start-Service Bower
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { Invoke-RestMethod 'http://127.0.0.1:4319/health' -TimeoutSec 2 | Out-Null; $healthy = $true; break } catch { Start-Sleep -Seconds 2 }
    }
    if (-not $healthy -or (Get-Service Bower).Status -ne 'Running') { throw 'collector-not-ready' }
    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $check = "-NoProfile -File `"$data\monitoring\Test-BowerCollectorHealth.ps1`" -TokenFile `"$data\secrets\ingest-token`" -QueuePath `"$data\data\bower.db`" -QueueMaxBytes 1073741824 -WecSubscription $subscriptionName -StateFile `"$data\monitoring\healthcheck-state.json`" -WriteEventLog"
    if (Get-ScheduledTask -TaskName 'BowerQualificationHealth' -ErrorAction SilentlyContinue) { throw 'health-task-exists' }
    Register-ScheduledTask -TaskName 'BowerQualificationHealth' -User SYSTEM -RunLevel Highest `
        -Action (New-ScheduledTaskAction -Execute $powershell -Argument $check) `
        -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew) | Out-Null
    [ordered]@{ runId = $env:BOWER_LAB_RUN; service = 'Running'; subscription = $subscriptionName;
        executableSha256 = (Get-FileHash "$install\Bower.Collector.exe").Hash.ToLowerInvariant();
        manifestSha256 = $env:BOWER_ARTIFACT_MANIFEST_SHA256; queueLimitBytes = 1073741824;
        nativeGenerationVerified = $false; destinationQueryVerified = $false; deliveryQualified = $false } | ConvertTo-Json -Compress
} catch {
    $failureMetadata = Get-WecSafeFailure $_
    if ($createdService) { Stop-Service Bower -ErrorAction SilentlyContinue }
    # Fail closed; retain owned installation for bounded diagnosis/host teardown.
    @{ setup = 'failed'; step = $step; failure = $failureMetadata; deliveryQualified = $false } | ConvertTo-Json -Depth 4 -Compress
    exit 1
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
