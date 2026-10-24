# Shared by Bower.Events and Bower.Management. Keep both copies byte-identical
# (powershell/tests/Repository.Tests.ps1 enforces it). Tokens stay SecureString in
# memory; they are never written to disk, the pipeline, or verbose/debug output.

function ConvertTo-BowerSecureString {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $secure = [securestring]::new()
    foreach ($character in $Value.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    $secure
}

function ConvertFrom-BowerSecureString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [securestring] $SecureString
    )

    [System.Net.NetworkCredential]::new([string]::Empty, $SecureString).Password
}

function Resolve-BowerToken {
    <#
    Normalises a token source result to { Token = SecureString; ExpiresOn = DateTimeOffset? }.
    Accepts a SecureString, a string (converted immediately), or an object with Token and
    optional ExpiresOn properties (Get-AzAccessToken output, or a provider's own object).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object] $Result,

        [Parameter(Mandatory)]
        [string] $Source
    )

    if ($Result -is [System.Collections.IList] -and $Result.Count -eq 1) {
        $Result = $Result[0]
    }

    $token = $Result
    $expiresOn = $null
    if ($null -ne $Result -and $Result -isnot [securestring] -and $Result -isnot [string]) {
        $token = $Result.Token
        $expiresOn = $Result.ExpiresOn
    }

    if ($token -is [string] -and $token.Length -gt 0) {
        $token = ConvertTo-BowerSecureString -Value $token
    }

    if ($token -isnot [securestring] -or $token.Length -eq 0) {
        throw [System.InvalidOperationException]::new(
            "$Source did not return a token. Return a SecureString or an object with a Token property.")
    }

    if ($expiresOn -is [datetime]) {
        $expiresOn = [datetimeoffset]$expiresOn
    }
    elseif ($expiresOn -isnot [datetimeoffset]) {
        $expiresOn = $null
    }

    [pscustomobject]@{
        Token     = $token
        ExpiresOn = $expiresOn
    }
}

function Test-BowerTokenFresh {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object] $Token
    )

    if ($null -eq $Token -or $null -eq $Token.Token) {
        return $false
    }

    # Unknown expiry (static token) is used as is; the API rejects it when it expires.
    $null -eq $Token.ExpiresOn -or $Token.ExpiresOn -gt [datetimeoffset]::UtcNow.AddMinutes(2)
}

function Get-BowerAzAccessToken {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ResourceUrl,

        [string] $TenantId
    )

    $command = Get-Command -Name Get-AzAccessToken -ErrorAction SilentlyContinue
    if (-not $command) {
        Import-Module -Name Az.Accounts -ErrorAction SilentlyContinue -Verbose:$false
        $command = Get-Command -Name Get-AzAccessToken -ErrorAction SilentlyContinue
    }

    if (-not $command) {
        throw [System.InvalidOperationException]::new(
            'Az.Accounts is not available. Install it (Install-Module Az.Accounts -Scope CurrentUser) and run Connect-AzAccount, or pass -AccessToken or -TokenProvider.')
    }

    $parameters = @{
        ResourceUrl   = $ResourceUrl
        ErrorAction   = 'Stop'
        WarningAction = 'SilentlyContinue'
    }
    if ($TenantId) {
        $parameters.TenantId = $TenantId
    }
    # Az.Accounts 5+ returns a SecureString by default; older releases need the switch.
    if ($command.Parameters.ContainsKey('AsSecureString')) {
        $parameters.AsSecureString = $true
    }

    Write-Verbose "Acquiring an Entra access token for resource '$ResourceUrl' through Az.Accounts."
    Resolve-BowerToken -Result (& $command @parameters) -Source 'Get-AzAccessToken'
}

function Invoke-BowerTokenProvider {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $TokenProvider
    )

    Write-Verbose 'Acquiring an access token from the token provider.'
    Resolve-BowerToken -Result (& $TokenProvider) -Source 'The token provider'
}
