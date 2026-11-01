# Fresh disposable Windows lab host only. Invoke through monitoring/run.py.
# Download and execute only AWS's HTTPS MSI after Windows Authenticode verification.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Assert-AwsCliSigner($Signature) {
    if ([string]$Signature.Status -cne 'Valid' -or -not $Signature.SignerCertificate) { throw 'signature-invalid' }
    $certificate = $Signature.SignerCertificate
    if ($certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Amazon Web Services, Inc.') {
        throw 'signature-publisher'
    }
    # Decode into separate DN attributes so the comma in the organization name
    # cannot be mistaken for a new attribute or matched as a substring.
    $attributes = $certificate.SubjectName.Decode([Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split '\r?\n'
    $organization = @($attributes | Where-Object { $_ -match '^O=' })
    if ($organization.Count -ne 1 -or $organization[0].Substring(2).Trim('"') -cne 'Amazon Web Services, Inc.') { throw 'signature-organization' }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1 -or -not (@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.5.5.7.3.3')) {
        throw 'signature-code-signing-purpose'
    }
}

function Copy-AwsCliDownload([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [long]$Advertised, [long]$Maximum) {
    if ($Advertised -lt 1 -or $Advertised -gt $Maximum) { throw 'download-size' }
    $buffer = New-Object byte[] 65536
    [long]$total = 0
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (($count = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        if ($clock.Elapsed.TotalSeconds -gt 300) { throw 'download-timeout' }
        $total += $count
        if ($total -gt $Maximum -or $total -gt $Advertised) { throw 'download-bound' }
        $OutputStream.Write($buffer, 0, $count)
    }
    if ($total -ne $Advertised) { throw 'download-length' }
}

function Test-AwsCliVersion([string]$Text) {
    # Suffixes change across AWS releases. Trust only the bounded CLI v2 version
    # prefix from the fixed executable installed by the verified MSI; emit no suffix.
    if ($Text.Length -gt 1024 -or $Text -cnotmatch '^aws-cli/(2\.[0-9]+\.[0-9]+)(?:\s|$)') { throw 'version-unexpected' }
    return $Matches[1]
}

$stage = $null
$verifiedInstaller = $null
$step = 'preflight'
$originalProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or
        $env:BOWER_LAB_RUN -cnotmatch '^bower-ws6-[0-9]{8}-[0-9]{6}$' -or
        $env:AWS_DEFAULT_REGION -cne 'ap-southeast-2') { throw 'owned-windows-required' }
    # The runner has already verified exact account/instance ownership. AWS CLI
    # cannot be used to recheck STS until it exists; never fall back to credentials.
    $executable = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
    $alreadyInstalled = [bool](Test-Path -LiteralPath $executable)
    $stage = Join-Path 'C:\ProgramData' ('BowerAwsCliStage-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = New-Object Security.Principal.SecurityIdentifier($identity)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $stage -AclObject $acl
    $step = 'download'
    # TLS 1.2 is enabled for this process only; certificate validation is unchanged.
    [Net.ServicePointManager]::SecurityProtocol = $originalProtocol -bor [Net.SecurityProtocolType]::Tls12
    $request = [Net.HttpWebRequest]::Create('https://awscli.amazonaws.com/AWSCLIV2.msi')
    $request.AllowAutoRedirect = $false
    $request.Timeout = 120000
    $request.ReadWriteTimeout = 30000
    $request.AutomaticDecompression = [Net.DecompressionMethods]::None
    $response = $request.GetResponse()
    try {
        if ([int]$response.StatusCode -ne 200 -or $response.ResponseUri.AbsoluteUri -cne 'https://awscli.amazonaws.com/AWSCLIV2.msi') { throw 'download-response' }
        $inputStream = $response.GetResponseStream()
        $path = Join-Path $stage 'AWSCLIV2.msi'
        $outputStream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-AwsCliDownload $inputStream $outputStream $response.ContentLength 134217728 }
        finally { $outputStream.Dispose(); $inputStream.Dispose() }
    } finally { $response.Dispose() }
    $step = 'signature'
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    Assert-AwsCliSigner $signature
    $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $thumbprint = $signature.SignerCertificate.Thumbprint
    $verifiedInstaller = @{ sha256 = $digest; signerThumbprint = $thumbprint;
        signerStatus = 'Valid'; publisher = 'Amazon Web Services, Inc.' }
    $step = 'install'
    # MSI log output is intentionally not retained; no install credentials exist.
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
        -ArgumentList @('/i', "`"$path`"", '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -notin @(0, 3010)) { throw 'installer-exit' }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'installed-executable-missing' }
    $step = 'version'
    $versionOutput = (& $executable --version 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'version-command' }
    $version = Test-AwsCliVersion $versionOutput
    @{ bootstrap = 'installed'; runId = $env:BOWER_LAB_RUN; version = $version; installerSha256 = $digest;
        signerThumbprint = $thumbprint; signerStatus = 'Valid'; publisher = 'Amazon Web Services, Inc.';
        previouslyInstalled = $alreadyInstalled;
        restartRequired = ($process.ExitCode -eq 3010); credentialsConfigured = $false } | ConvertTo-Json -Compress
} catch {
    $allowed = @('signature-invalid', 'signature-publisher', 'signature-organization', 'signature-code-signing-purpose',
        'download-size', 'download-bound', 'download-length', 'download-timeout', 'version-unexpected', 'owned-windows-required',
        'download-response', 'installer-exit', 'installed-executable-missing', 'version-command')
    $code = if ($allowed -ccontains $_.Exception.Message) { $_.Exception.Message } else { 'unclassified' }
    @{ bootstrap = 'failed'; step = $step; staticCode = $code; exceptionType = $_.Exception.GetType().FullName;
        category = $_.CategoryInfo.Category.ToString(); scriptLine = $_.InvocationInfo.ScriptLineNumber;
        verifiedInstaller = $verifiedInstaller } | ConvertTo-Json -Depth 4 -Compress
    exit 1
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $originalProtocol
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
