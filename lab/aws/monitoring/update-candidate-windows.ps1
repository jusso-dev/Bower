# Owned disposable lab only. Update only the two pinned native files; retain all state.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Assert-CandidatePath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'candidate-reparse-path' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}

function New-CandidatePrivateDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Guarded disposable-lab transaction; skipping a step would leave unsafe state.')]
    param([string]$Path)
    New-Item -ItemType Directory -Path $Path | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = New-Object Security.Principal.SecurityIdentifier($identity)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-CandidateFailure($Failure) {
    $codes = @('candidate-reparse-path', 'candidate-acl-owner', 'candidate-acl-rules',
        'candidate-acl-mismatch', 'candidate-acl-callback-required', 'candidate-service-sid',
        'candidate-baseline-acl-changed', 'candidate-not-ready')
    return @{ exceptionType = $Failure.Exception.GetType().FullName;
        innerExceptionType = $(if ($Failure.Exception.InnerException) { $Failure.Exception.InnerException.GetType().FullName } else { $null });
        hResult = $Failure.Exception.HResult; category = $Failure.CategoryInfo.Category.ToString();
        scriptLine = $(if ($Failure.InvocationInfo) { $Failure.InvocationInfo.ScriptLineNumber } else { 0 });
        staticCode = $(if ($codes -ccontains $Failure.Exception.Message) { $Failure.Exception.Message } else { 'unclassified' }) }
}

function New-CandidateNativeAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an ACL in memory and does not alter a resource.')]
    param([string]$OwnerSid, [string]$GroupSid, [string]$ServiceSid)
    if ($OwnerSid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or $GroupSid -cnotin @('S-1-5-18', 'S-1-5-32-544')) { throw 'candidate-acl-owner' }
    if ($ServiceSid -cne 'S-1-5-80-3437565569-4244630927-521338199-147183979-3886342086') { throw 'candidate-service-sid' }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($OwnerSid)))
    $acl.SetGroup((New-Object Security.Principal.SecurityIdentifier($GroupSid)))
    foreach ($identity in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = New-Object Security.Principal.SecurityIdentifier($identity)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,
            [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $service = New-Object Security.Principal.SecurityIdentifier($ServiceSid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($service,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute, [Security.AccessControl.AccessControlType]::Allow)))
    return $acl
}

function Get-CandidateAclFingerprint($Acl) {
    $rules = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}:{1}:{2}:{3}:{4}:{5}' -f $_.IdentityReference.Value, [long]$_.FileSystemRights,
            $_.AccessControlType, $_.IsInherited, $_.InheritanceFlags, $_.PropagationFlags
    } | Sort-Object)
    $material = @($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value,
        $Acl.GetGroup([Security.Principal.SecurityIdentifier]).Value, [string]$Acl.AreAccessRulesProtected, ($rules -join '|')) -join '|'
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Get-CandidateExpectedAcl([string]$Path, [string]$ServiceSid) {
    Assert-CandidatePath $Path
    $actual = Get-Acl -LiteralPath $Path
    $owner = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $group = $actual.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $expected = New-CandidateNativeAcl -OwnerSid $owner -GroupSid $group -ServiceSid $ServiceSid
    $expectedRights = @{}
    foreach ($rule in $expected.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $expectedRights[$rule.IdentityReference.Value] = [long]$rule.FileSystemRights
    }
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $seen = @{}
    if ($rules.Count -ne 3) { throw 'candidate-acl-rules' }
    foreach ($rule in $rules) {
        $identity = $rule.IdentityReference.Value
        if (-not $expectedRights.ContainsKey($identity) -or $seen.ContainsKey($identity) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [long]$rule.FileSystemRights -ne $expectedRights[$identity] -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'candidate-acl-rules' }
        $seen[$identity] = $true
    }
    # Known inherited and protected-explicit baselines are accepted. Unknown
    # grants/denials/owners are never silently broadened or normalized away.
    return $expected
}

function Assert-CandidateNativeAcl([string]$Path, $Expected) {
    Assert-CandidatePath $Path
    if ((Get-CandidateAclFingerprint (Get-Acl -LiteralPath $Path)) -cne (Get-CandidateAclFingerprint $Expected)) { throw 'candidate-acl-mismatch' }
}

function Set-CandidateNativeAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Required atomic update step; the guarded caller owns execution intent.')]
    param([string]$Path, $Expected)
    Assert-CandidatePath $Path
    Set-Acl -LiteralPath $Path -AclObject $Expected
    Assert-CandidateNativeAcl $Path $Expected
}

function Expand-CandidateArchive([string]$Path, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    $files = @('collector/Bower.Collector.exe', 'collector/e_sqlite3.dll')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [long]$total = 0
    try {
        if ($archive.Entries.Count -notin @(2, 3)) { throw 'candidate-archive-count' }
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            $mode = ($entry.ExternalAttributes -shr 16) -band 61440
            if ((($files + 'collector/') -cnotcontains $name) -or -not $seen.Add($name) -or
                $mode -notin @(0, 16384, 32768) -or ($entry.ExternalAttributes -band 1024)) { throw 'candidate-archive-name' }
            if ($name -ceq 'collector/') {
                if ($entry.Length -ne 0 -or $mode -eq 32768) { throw 'candidate-archive-directory' }
            } else {
                if ($entry.Length -lt 1 -or $entry.Length -gt 536870912 -or $mode -eq 16384) { throw 'candidate-archive-size' }
                $total += $entry.Length
            }
        }
        if ($total -gt 536870912 -or -not $seen.Contains($files[0]) -or -not $seen.Contains($files[1])) { throw 'candidate-archive-bound' }
        $buffer = New-Object byte[] 65536
        foreach ($name in $files) {
            $entry = $archive.GetEntry($name)
            $target = Join-Path $Destination ([IO.Path]::GetFileName($name))
            $inputStream = $entry.Open(); $outputStream = $null
            try {
                $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                [long]$count = 0
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $count += $read
                    if ($count -gt $entry.Length) { throw 'candidate-expanded-bound' }
                    $outputStream.Write($buffer, 0, $read)
                }
                if ($count -ne $entry.Length) { throw 'candidate-expanded-length' }
                $outputStream.Flush($true)
            } finally { if ($outputStream) { $outputStream.Dispose() }; $inputStream.Dispose() }
        }
    } finally { $archive.Dispose() }
}

function Get-CandidateFileHash([string]$Directory) {
    $result = @{}
    foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') { $result[$name] = (Get-FileHash -LiteralPath (Join-Path $Directory $name)).Hash.ToLowerInvariant() }
    return $result
}

function Invoke-CandidateSwap([string]$Install, [string]$Candidate, [string]$Backup,
    [scriptblock]$Stop, [scriptblock]$Start, [scriptblock]$Healthy,
    [scriptblock]$Protect, [scriptblock]$Verify) {
    if (-not $Protect -or -not $Verify) { throw 'candidate-acl-callback-required' }
    $files = @('Bower.Collector.exe', 'e_sqlite3.dll')
    $old = Get-CandidateFileHash $Install; $new = Get-CandidateFileHash $Candidate
    foreach ($name in $files) {
        Copy-Item -LiteralPath (Join-Path $Install $name) -Destination (Join-Path $Backup $name)
        & $Protect (Join-Path $Backup $name) $name
        & $Protect (Join-Path $Candidate $name) $name
    }
    $changed = New-Object 'System.Collections.Generic.List[string]'
    try {
        & $Stop
        foreach ($name in $files) {
            # Real NTFS testing showed ReplaceFile can lose inherited service RX.
            # Candidate/backup ACLs are explicit, and the live result is re-applied
            # and verified before either binary is allowed to start.
            [IO.File]::Replace((Join-Path $Candidate $name), (Join-Path $Install $name), [Management.Automation.Language.NullString]::Value)
            $changed.Add($name)
            & $Protect (Join-Path $Install $name) $name
            & $Verify (Join-Path $Install $name) $name
        }
        & $Start
        if (-not (& $Healthy)) { throw 'candidate-not-ready' }
        return @{ updated = $true; oldSha256 = $old; newSha256 = $new; rollbackPerformed = $false }
    } catch {
        $failure = Get-CandidateFailure $_
        $restored = $false
        $rollbackFailure = $null
        try {
            & $Stop
            foreach ($name in $files) {
                $temporary = Join-Path $Backup ($name + '.restore')
                Copy-Item -LiteralPath (Join-Path $Backup $name) -Destination $temporary
                & $Protect $temporary $name
                [IO.File]::Replace($temporary, (Join-Path $Install $name), [Management.Automation.Language.NullString]::Value)
                & $Protect (Join-Path $Install $name) $name
                & $Verify (Join-Path $Install $name) $name
            }
            & $Start
            $actual = Get-CandidateFileHash $Install
            $restored = [bool]((& $Healthy) -and $actual[$files[0]] -ceq $old[$files[0]] -and $actual[$files[1]] -ceq $old[$files[1]])
        } catch { $restored = $false; $rollbackFailure = Get-CandidateFailure $_ }
        return @{ updated = $false; oldSha256 = $old; newSha256 = $new; rollbackPerformed = $true;
            rollbackSucceeded = $restored; filesChanged = @($changed); failure = $failure; rollbackFailure = $rollbackFailure }
    }
}

function Get-CandidateQueueCount {
    $token = [IO.File]::ReadAllText('C:\ProgramData\Bower\secrets\ingest-token').Trim()
    try { $status = Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 5 -MaximumRedirection 0 }
    finally { $token = $null }
    $counts = @{}
    foreach ($name in 'queued', 'retrying', 'uploading', 'delivered', 'deadLettered', 'totalBytes', 'undeliveredBytes') {
        $value = $status.queue.$name
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0) { throw 'queue-count-invalid' }
        $counts[$name] = $value
    }
    return $counts
}

$stage = $null; $lock = $null; $step = 'preflight'
try {
    $run = $env:BOWER_LAB_RUN; $commit = $env:BOWER_CANDIDATE_COMMIT; $digest = $env:BOWER_CANDIDATE_SHA256
    if ($env:OS -ne 'Windows_NT' -or $run -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or
        $env:BOWER_LAB_BUCKET -cnotmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or
        $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2' -or $commit -cnotmatch '^[a-f0-9]{40}$' -or $digest -cnotmatch '^[a-f0-9]{64}$') { throw 'candidate-scope' }
    $root = 'C:\ProgramData\Bower\monitoring'; $install = 'C:\Program Files\Bower'
    Assert-CandidatePath $root; Assert-CandidatePath $install
    foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') { Assert-CandidatePath (Join-Path $install $name) }
    $owner = Get-Content "$root\qualification.json" -Raw | ConvertFrom-Json
    if ($owner.runId -cne $run) { throw 'candidate-owner' }
    $lock = [IO.File]::Open("$root\generator.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    if (Get-NetFirewallRule -Name ('BowerOutage-' + $run) -ErrorAction SilentlyContinue) { throw 'candidate-during-outage' }
    $service = Get-CimInstance Win32_Service -Filter "Name='Bower'"
    if ($service.StartName -ine 'NT SERVICE\Bower' -or $service.PathName.Trim('"') -ine "$install\Bower.Collector.exe" -or $service.State -ne 'Running') { throw 'candidate-service-binding' }
    $serviceSid = (New-Object Security.Principal.NTAccount('NT SERVICE\Bower')).Translate([Security.Principal.SecurityIdentifier]).Value
    $expectedAcls = @{}; $baselineAcls = @{}; $baselineAclHashes = @{}; $expectedAclHashes = @{}
    foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
        $path = Join-Path $install $name
        $expectedAcls[$name] = Get-CandidateExpectedAcl $path $serviceSid
        $acl = Get-Acl -LiteralPath $path
        $baselineAcls[$name] = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor
            [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)
        $baselineAclHashes[$name] = Get-CandidateAclFingerprint $acl
        $expectedAclHashes[$name] = Get-CandidateAclFingerprint $expectedAcls[$name]
    }
    $aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
    $account = & $aws sts get-caller-identity --query Account --output text 2>$null
    if ($LASTEXITCODE -ne 0 -or $account -ne '959038055523') { throw 'candidate-account' }
    $before = Get-CandidateQueueCount
    $step = 'download'
    $key = "artifacts/qualification/$run/candidate/$commit/windows/collector.zip"
    $sizeText = & $aws s3api head-object --bucket $env:BOWER_LAB_BUCKET --key $key --query ContentLength --output text 2>$null
    [long]$size = 0
    if ($LASTEXITCODE -ne 0 -or -not [long]::TryParse([string]$sizeText, [ref]$size) -or $size -lt 1 -or $size -gt 536870912) { throw 'candidate-download-bound' }
    $stage = Join-Path $install ('.candidate-' + [Guid]::NewGuid().ToString('N'))
    New-CandidatePrivateDirectory $stage
    $archive = Join-Path $stage 'collector.zip'
    & $aws s3 cp "s3://$($env:BOWER_LAB_BUCKET)/$key" $archive --only-show-errors *> $null
    if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $archive).Length -ne $size -or (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() -cne $digest) { throw 'candidate-digest' }
    $step = 'archive'
    Expand-CandidateArchive $archive $stage
    $backup = Join-Path $install ('.rollback-' + $commit + '-' + [Guid]::NewGuid().ToString('N'))
    New-CandidatePrivateDirectory $backup
    $baselineAcls | ConvertTo-Json | Set-Content (Join-Path $backup 'baseline-acl.json') -Encoding UTF8
    $stop = { Stop-Service Bower; (Get-Service Bower).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
    $start = { Start-Service Bower }
    $healthy = {
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            try {
                if ((Get-Service Bower).Status -eq 'Running') { Get-CandidateQueueCount | Out-Null; return $true }
            } catch { Write-Verbose 'Candidate service health is not ready; retrying.' }
            Start-Sleep -Seconds 2
        }
        return $false
    }
    $step = 'swap'
    foreach ($name in 'Bower.Collector.exe', 'e_sqlite3.dll') {
        if ((Get-CandidateAclFingerprint (Get-Acl -LiteralPath (Join-Path $install $name))) -cne $baselineAclHashes[$name]) { throw 'candidate-baseline-acl-changed' }
    }
    $protect = { param($Path, $Name) Set-CandidateNativeAcl $Path $expectedAcls[$Name] }
    $verify = { param($Path, $Name) Assert-CandidateNativeAcl $Path $expectedAcls[$Name] }
    $result = Invoke-CandidateSwap -Install $install -Candidate $stage -Backup $backup -Stop $stop -Start $start -Healthy $healthy -Protect $protect -Verify $verify
    $result.runId = $run; $result.candidateCommit = $commit; $result.archiveSha256 = $digest
    $result.rollbackDirectory = $backup; $result.queueBefore = $before
    $result.configurationChanged = $false; $result.queueReplaced = $false; $result.destinationQueryVerified = $false
    $result.baselineAclSha256 = $baselineAclHashes; $result.expectedAclSha256 = $expectedAclHashes
    $result.serviceReady = [bool]($result.updated -or ($result.ContainsKey('rollbackSucceeded') -and $result.rollbackSucceeded))
    try { $result.queueAfter = Get-CandidateQueueCount } catch { $result.queueAfter = $null }
    $result | ConvertTo-Json -Depth 6 -Compress
    if (-not $result.updated) { exit 1 }
} catch {
    @{ candidateUpdate = 'failed'; step = $step; failure = (Get-CandidateFailure $_) } | ConvertTo-Json -Depth 4 -Compress
    exit 1
} finally {
    if ($lock) { $lock.Dispose() }
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
