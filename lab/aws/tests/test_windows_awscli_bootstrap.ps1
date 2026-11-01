# Parse and test only pure guards. Never download or install AWS CLI.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$path = Join-Path $PSScriptRoot '../monitoring/bootstrap-windows-awscli.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'bootstrap parse' }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
$tests = 0
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'guard accepted invalid fixture' }
    $script:tests++
}
function New-SignerFixture {
    $subject = [pscustomobject]@{ Text = "CN=`"Amazon Web Services, Inc.`"`nO=`"Amazon Web Services, Inc.`"`nC=US" }
    $subject | Add-Member -MemberType ScriptMethod -Name Decode -Value { param($flags) return $this.Text }
    $certificate = [pscustomobject]@{ Publisher = 'Amazon Web Services, Inc.'; SubjectName = $subject;
        Extensions = @([pscustomobject]@{ Oid = [pscustomobject]@{ Value = '2.5.29.37' };
            EnhancedKeyUsages = @([pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.3' }) }) }
    $certificate | Add-Member -MemberType ScriptMethod -Name GetNameInfo -Value { param($type, $issuer) return $this.Publisher }
    return [pscustomobject]@{ Status = 'Valid'; SignerCertificate = $certificate }
}
$signature = New-SignerFixture
Assert-AwsCliSigner $signature; $tests++
foreach ($status in 'NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError') {
    $signature = New-SignerFixture; $signature.Status = $status
    Assert-Rejected { Assert-AwsCliSigner $signature }
}
foreach ($publisher in 'Amazon Web Services, Inc. Evil', 'amazon web services, inc.', 'Amazon') {
    $signature = New-SignerFixture; $signature.SignerCertificate.Publisher = $publisher
    Assert-Rejected { Assert-AwsCliSigner $signature }
}
$signature = New-SignerFixture
$signature.SignerCertificate.SubjectName.Text = "CN=Amazon Web Services, Inc.`nO=Foreign Publisher"
Assert-Rejected { Assert-AwsCliSigner $signature }
$signature = New-SignerFixture
$signature.SignerCertificate.Extensions[0].EnhancedKeyUsages[0].Value = '1.3.6.1.5.5.7.3.1'
Assert-Rejected { Assert-AwsCliSigner $signature }
$signature = New-SignerFixture; $signature.SignerCertificate = $null
Assert-Rejected { Assert-AwsCliSigner $signature }
foreach ($case in @(@(8,8,8,$true), @(9,8,8,$false), @(7,8,8,$false), @(8,8,7,$false), @(1,-1,8,$false))) {
    $inputStream = New-Object IO.MemoryStream (,([byte[]](0..($case[0]-1))))
    $outputStream = New-Object IO.MemoryStream
    try {
        if ($case[3]) {
            Copy-AwsCliDownload $inputStream $outputStream $case[1] $case[2]
            if ($outputStream.Length -ne 8) { throw 'download-copy' }; $tests++
        } else { Assert-Rejected { Copy-AwsCliDownload $inputStream $outputStream $case[1] $case[2] } }
    } finally { $inputStream.Dispose(); $outputStream.Dispose() }
}
if ((Test-AwsCliVersion 'aws-cli/2.31.0 Python/3.13.7 Windows/2022Server exe/AMD64') -cne '2.31.0') { throw 'valid version' }; $tests++
Assert-Rejected { Test-AwsCliVersion 'aws-cli/1.20.0 Python/3.9 Windows/10 exe/AMD64' }
Assert-Rejected { Test-AwsCliVersion 'aws-cli/2.31.0evil Python/3.13.7 Windows/2022Server' }
Assert-Rejected { Test-AwsCliVersion 'unexpected version output' }
Assert-Rejected { Test-AwsCliVersion ('aws-cli/2.31.0 ' + ('x' * 1024)) }
foreach ($suffix in '', ' Python/3.13.7 Windows/2022Server exe/AMD64', ' Python/3.13.9 Windows/2022Server exe/AMD64 prompt/off',
    ' Python/3.13.9 Windows/2022Server exe/AMD64.win.2022', ' future-release-metadata') {
    if ((Test-AwsCliVersion ('aws-cli/2.31.0' + $suffix)) -cne '2.31.0') { throw 'CLI suffix compatibility' }; $tests++
}
Write-Output "Windows AWS CLI bootstrap validation: $tests checks passed (no download/install actions)."
