# Optional AWS Lambda Function URL target (AuthType AWS_IAM). Isolated here so the
# collector and Azure Function paths never load or depend on AWS tooling.
# Credentials come from AWS.Tools.Common; the module never reads AWS files itself.

function Get-BowerHexSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-BowerHmacSha256 {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Key,

        [Parameter(Mandatory)]
        [string] $Data
    )

    , [System.Security.Cryptography.HMACSHA256]::HashData($Key, [System.Text.Encoding]::UTF8.GetBytes($Data))
}

function ConvertTo-BowerSigV4Encoded {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    # RFC 3986 unreserved characters stay literal; EscapeDataString already matches that.
    [uri]::EscapeDataString($Value)
}

function Get-BowerSigV4Authorization {
    <#
    Computes an AWS Signature Version 4 Authorization header value for the given request.
    Headers must contain every header to sign (including host). Returns the header value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Method,

        [Parameter(Mandatory)]
        [uri] $Uri,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Headers,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Payload,

        [Parameter(Mandatory)]
        [string] $Region,

        [Parameter(Mandatory)]
        [string] $Service,

        [Parameter(Mandatory)]
        [string] $AccessKeyId,

        [Parameter(Mandatory)]
        [securestring] $SecretAccessKey,

        [Parameter(Mandatory)]
        [string] $AmzDate
    )

    $date = $AmzDate.Substring(0, 8)
    $segments = $Uri.AbsolutePath.Split('/') | ForEach-Object { ConvertTo-BowerSigV4Encoded -Value $_ }
    $canonicalUri = $segments -join '/'
    if ([string]::IsNullOrEmpty($canonicalUri)) {
        $canonicalUri = '/'
    }

    $query = @()
    if ($Uri.Query.Length -gt 1) {
        $query = foreach ($pair in $Uri.Query.Substring(1).Split('&')) {
            $parts = $pair.Split('=', 2)
            $name = ConvertTo-BowerSigV4Encoded -Value ([uri]::UnescapeDataString($parts[0]))
            $value = if ($parts.Count -gt 1) { ConvertTo-BowerSigV4Encoded -Value ([uri]::UnescapeDataString($parts[1])) } else { '' }
            [pscustomobject]@{ Name = $name; Value = $value }
        }
    }
    $canonicalQuery = (@($query | Sort-Object -Property Name, Value -CaseSensitive | ForEach-Object { "$($_.Name)=$($_.Value)" })) -join '&'

    $normalized = [System.Collections.Generic.SortedDictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $Headers.Keys) {
        $normalized[$key.ToString().ToLowerInvariant()] = ([regex]::Replace([string]$Headers[$key], '\s+', ' ')).Trim()
    }
    $canonicalHeaders = (@($normalized.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)`n" })) -join ''
    $signedHeaders = @($normalized.Keys) -join ';'

    $canonicalRequest = @(
        $Method.ToUpperInvariant()
        $canonicalUri
        $canonicalQuery
        $canonicalHeaders
        $signedHeaders
        (Get-BowerHexSha256 -Bytes $Payload)
    ) -join "`n"

    $scope = "$date/$Region/$Service/aws4_request"
    $stringToSign = @(
        'AWS4-HMAC-SHA256'
        $AmzDate
        $scope
        (Get-BowerHexSha256 -Bytes ([System.Text.Encoding]::UTF8.GetBytes($canonicalRequest)))
    ) -join "`n"

    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes('AWS4' + (ConvertFrom-BowerSecureString -SecureString $SecretAccessKey))
    try {
        $key = Get-BowerHmacSha256 -Key $secretBytes -Data $date
        $key = Get-BowerHmacSha256 -Key $key -Data $Region
        $key = Get-BowerHmacSha256 -Key $key -Data $Service
        $key = Get-BowerHmacSha256 -Key $key -Data 'aws4_request'
        $signature = [System.Convert]::ToHexString((Get-BowerHmacSha256 -Key $key -Data $stringToSign)).ToLowerInvariant()
    }
    finally {
        [array]::Clear($secretBytes, 0, $secretBytes.Length)
    }

    "AWS4-HMAC-SHA256 Credential=$AccessKeyId/$scope, SignedHeaders=$signedHeaders, Signature=$signature"
}

function Get-BowerLambdaRegion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri,

        [string] $Region
    )

    if ($Region) {
        return $Region
    }
    if ($Uri.Host -match '^[a-z0-9]+\.lambda-url\.([a-z0-9-]+)\.on\.aws$') {
        return $Matches[1]
    }
    throw [System.ArgumentException]::new('Cannot infer the AWS region from the Function URL host; pass -AwsRegion.')
}

function Get-BowerAwsCredential {
    <#
    Resolves AWS credentials through AWS.Tools.Common: a named profile, the shell default
    set by Set-AWSCredential, or the SDK default chain (environment, SSO, container/instance
    roles). Returns { AccessKeyId; SecretAccessKey (SecureString); SessionToken (SecureString) }.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $ProfileName
    )

    if (-not (Get-Command -Name Get-AWSCredential -ErrorAction SilentlyContinue)) {
        Import-Module -Name AWS.Tools.Common -ErrorAction SilentlyContinue -Verbose:$false
    }
    if (-not (Get-Command -Name Get-AWSCredential -ErrorAction SilentlyContinue)) {
        throw [System.InvalidOperationException]::new(
            'Send-BowerSecurityEvent -Target Lambda signs requests with SigV4 and needs AWS.Tools.Common (Install-Module AWS.Tools.Common -Scope CurrentUser).')
    }

    $credentials = if ($ProfileName) {
        Get-AWSCredential -ProfileName $ProfileName -ErrorAction Stop
    }
    else {
        Get-AWSCredential -ErrorAction SilentlyContinue
    }
    if ($null -eq $credentials) {
        foreach ($typeName in 'Amazon.Runtime.Credentials.DefaultAWSCredentialsIdentityResolver', 'Amazon.Runtime.FallbackCredentialsFactory') {
            $type = $typeName -as [type]
            if ($type) {
                $credentials = $type::GetCredentials()
                break
            }
        }
    }
    if ($null -eq $credentials) {
        throw [System.InvalidOperationException]::new('No AWS credentials were found. Pass -AwsProfileName or configure the AWS SDK default credential chain.')
    }

    $immutable = $credentials.GetCredentials()
    [pscustomobject]@{
        AccessKeyId     = $immutable.AccessKey
        SecretAccessKey = ConvertTo-BowerSecureString -Value $immutable.SecretKey
        SessionToken    = if ($immutable.Token) { ConvertTo-BowerSecureString -Value $immutable.Token } else { $null }
    }
}

function Get-BowerLambdaSignedHeader {
    <# Signs one attempt. Called per attempt by Invoke-BowerHttpRequest -HeaderFactory. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri,

        [Parameter(Mandatory)]
        [byte[]] $Payload,

        [Parameter(Mandatory)]
        [string] $Region,

        [Parameter(Mandatory)]
        [pscustomobject] $AwsCredential
    )

    $amzDate = [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ', [cultureinfo]::InvariantCulture)
    $hostHeader = if ($Uri.IsDefaultPort) { $Uri.Host } else { "$($Uri.Host):$($Uri.Port)" }
    $signed = [ordered]@{
        'host'                 = $hostHeader
        'x-amz-content-sha256' = Get-BowerHexSha256 -Bytes $Payload
        'x-amz-date'           = $amzDate
    }
    if ($AwsCredential.SessionToken) {
        $signed['x-amz-security-token'] = ConvertFrom-BowerSecureString -SecureString $AwsCredential.SessionToken
    }
    $authorization = Get-BowerSigV4Authorization -Method 'POST' -Uri $Uri -Headers $signed -Payload $Payload `
        -Region $Region -Service 'lambda' -AccessKeyId $AwsCredential.AccessKeyId -SecretAccessKey $AwsCredential.SecretAccessKey -AmzDate $amzDate
    $headers = @{ Authorization = $authorization }
    foreach ($name in @($signed.Keys)) {
        if ($name -ne 'host') {
            $headers[$name] = $signed[$name]
        }
    }
    $headers
}
