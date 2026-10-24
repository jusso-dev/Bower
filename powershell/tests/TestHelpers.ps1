# Dot-sourced by the *.Tests.ps1 files. Nothing here talks to a network or cloud.

$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:ModulesRoot = Join-Path $script:RepositoryRoot 'powershell/modules'

function Import-BowerTestModule {
    param([Parameter(Mandatory)][string] $Name)
    Import-Module (Join-Path $script:ModulesRoot "$Name/$Name.psd1") -Force -ErrorAction Stop
}

function New-TestSecureString {
    param([Parameter(Mandatory)][string] $Value)
    $secure = [securestring]::new()
    foreach ($character in $Value.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    $secure
}

function ConvertFrom-TestSecureString {
    param([Parameter(Mandatory)][securestring] $Value)
    [System.Net.NetworkCredential]::new('', $Value).Password
}

# Builds the ErrorRecord Invoke-RestMethod throws for a non-success status code.
function New-HttpErrorRecord {
    param(
        [Parameter(Mandatory)][int] $StatusCode,
        [string] $Body,
        [Nullable[double]] $RetryAfterSeconds,
        [Nullable[datetimeoffset]] $RetryAfterDate
    )
    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$StatusCode)
    if ($null -ne $RetryAfterSeconds) {
        $response.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([timespan]::FromSeconds($RetryAfterSeconds))
    }
    elseif ($null -ne $RetryAfterDate) {
        $response.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([datetimeoffset]$RetryAfterDate)
    }
    $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new("Response status code does not indicate success: $StatusCode.", $response)
    $record = [System.Management.Automation.ErrorRecord]::new($exception, 'WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeRestMethodCommand', 'InvalidOperation', $null)
    if ($Body) {
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($Body)
    }
    $record
}

function Get-TestBodyText {
    param([AllowNull()][object] $Body)
    if ($Body -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($Body) }
    [string]$Body
}

function New-TestEvent {
    param([string] $EventId = 'evt-0001')
    [ordered]@{
        schemaVersion = '1.0.0'
        eventId       = $EventId
        timeGenerated = '2026-10-24T01:02:03.0000000+00:00'
        eventCategory = 'authentication'
        eventType     = 'user_sign_in'
        eventAction   = 'sign-in'
        eventResult   = 'success'
        application   = [ordered]@{ name = 'payroll'; environment = 'test' }
    }
}
