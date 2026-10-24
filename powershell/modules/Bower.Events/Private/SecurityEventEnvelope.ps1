# Envelope rules mirror schemas/envelope/security-event.schema.json (1.0.0). The module
# embeds them so it works outside the repository; Repository.Tests.ps1 checks for drift.
# Property names are case-sensitive, as in the JSON schema.

$script:EnvelopeSchemaVersion = '1.0.0'
$script:MaximumEventBytes = 1048576

$script:EnvelopeProperties = @(
    'schemaVersion', 'eventId', 'eventOriginalId', 'timeGenerated', 'timeObserved',
    'eventCategory', 'eventType', 'eventAction', 'eventResult', 'eventSeverity',
    'eventOutcomeReason', 'application', 'actor', 'target', 'source', 'request',
    'change', 'security', 'collector', 'labels', 'attributes'
)
$script:EnvelopeRequired = @(
    'schemaVersion', 'eventId', 'timeGenerated', 'eventCategory', 'eventType',
    'eventAction', 'eventResult', 'application'
)
$script:EventCategories = @(
    'authentication', 'authorisation', 'identity-management', 'administrative-activity',
    'data-access', 'application-security', 'api-security', 'collector-health'
)
$script:EventResults = @('unknown', 'success', 'failure', 'denied')
$script:EventSeverities = @('informational', 'low', 'medium', 'high', 'critical')
$script:ActorTypes = @('human', 'service', 'machine', 'system', 'unknown')
$script:EventTypePattern = '^[a-z][a-z0-9_]{2,127}$'

# name -> maximum length (code points). Required members are listed separately.
$script:NestedStringLimits = @{
    application = [ordered]@{ name = 128; version = 64; environment = 64; instance = 256; tenantId = 256 }
    actor       = [ordered]@{ userId = 256; username = 256; displayName = 256; role = 256 }
    target      = [ordered]@{ type = 128; id = 256; name = 256 }
    source      = [ordered]@{ ipAddress = 64; hostname = 256 }
    request     = [ordered]@{ correlationId = 256; traceId = 128; sessionId = 256; method = 16; path = 2048 }
}
$script:NestedProperties = @{
    application = @('name', 'version', 'environment', 'instance', 'tenantId')
    actor       = @('userId', 'username', 'displayName', 'type', 'role')
    target      = @('type', 'id', 'name')
    source      = @('ipAddress', 'hostname', 'port')
    request     = @('correlationId', 'traceId', 'sessionId', 'method', 'path', 'statusCode')
}

function ConvertTo-BowerEnvelopeData {
    <# Converts hashtables / PSCustomObjects (recursively) into ordered dictionaries. #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()]
        [object] $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $result[[string]$key] = ConvertTo-BowerEnvelopeData -InputObject $InputObject[$key]
        }
        return $result
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $result = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-BowerEnvelopeData -InputObject $property.Value
        }
        return $result
    }
    if ($InputObject -is [datetimeoffset]) {
        return $InputObject.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
    }
    if ($InputObject -is [datetime]) {
        return ([datetimeoffset]$InputObject).ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
    }
    if ($InputObject -is [string] -or $InputObject -is [valuetype]) {
        return $InputObject
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        return , @(foreach ($item in $InputObject) { ConvertTo-BowerEnvelopeData -InputObject $item })
    }
    $InputObject
}

function Get-BowerCodePointCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $count = 0
    foreach ($null in $Value.EnumerateRunes()) {
        $count++
    }
    $count
}

function Test-BowerDateTimeString {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object] $Value
    )

    if ($Value -isnot [string]) {
        return $false
    }
    $parsed = [datetimeoffset]::MinValue
    # RFC 3339 date-time: require a date, a time and an explicit offset or Z.
    $Value -match '^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$' -and
    [datetimeoffset]::TryParse($Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
}

function Get-BowerStringProblem {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [AllowNull()]
        [object] $Value,

        [Parameter(Mandatory)]
        [int] $MaximumLength,

        [int] $MinimumLength = 0,

        [switch] $AllowNull
    )

    if ($null -eq $Value) {
        if (-not $AllowNull) {
            "$Path must be a string."
        }
        return
    }
    if ($Value -isnot [string]) {
        "$Path must be a string."
        return
    }
    $length = Get-BowerCodePointCount -Value $Value
    if ($length -lt $MinimumLength -or $length -gt $MaximumLength) {
        if ($MinimumLength -gt 0) {
            "$Path must be $MinimumLength-$MaximumLength characters."
        }
        else {
            "$Path must be at most $MaximumLength characters."
        }
    }
}

function Get-BowerUnknownPropertyProblem {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Data,

        [Parameter(Mandatory)]
        [string[]] $Allowed
    )

    foreach ($key in $Data.Keys) {
        if ($Allowed -ccontains $key) {
            continue
        }
        $suggestion = $Allowed | Where-Object { $_ -eq $key } | Select-Object -First 1
        if ($suggestion) {
            "$Path property '$key' is not allowed; property names are case-sensitive (use '$suggestion')."
        }
        else {
            "$Path property '$key' is not allowed."
        }
    }
}

function Get-BowerNestedProblem {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [AllowNull()]
        [object] $Value,

        [switch] $Required
    )

    if ($null -eq $Value) {
        if ($Required) {
            "$Name is required."
        }
        return
    }
    if ($Value -isnot [System.Collections.IDictionary]) {
        "$Name must be an object."
        return
    }

    Get-BowerUnknownPropertyProblem -Path $Name -Data $Value -Allowed $script:NestedProperties[$Name]
    $limits = $script:NestedStringLimits[$Name]
    $requiredMembers = switch ($Name) {
        'application' { @('name', 'environment') }
        'target' { @('type') }
        default { @() }
    }
    foreach ($member in $limits.Keys) {
        $isRequired = $requiredMembers -contains $member
        if (-not $Value.Contains($member)) {
            if ($isRequired) {
                "$Name.$member is required."
            }
            continue
        }
        $minimum = if ($isRequired) { 1 } else { 0 }
        Get-BowerStringProblem -Path "$Name.$member" -Value $Value[$member] -MaximumLength $limits[$member] -MinimumLength $minimum -AllowNull:(-not $isRequired)
    }

    if ($Name -eq 'actor' -and $Value.Contains('type') -and $script:ActorTypes -cnotcontains $Value['type']) {
        "actor.type must be one of: $($script:ActorTypes -join ', ')."
    }
    if ($Name -eq 'source' -and $Value.Contains('port') -and $null -ne $Value['port']) {
        if (-not (Test-BowerInteger -Value $Value['port'] -Minimum 0 -Maximum 65535)) {
            'source.port must be an integer between 0 and 65535.'
        }
    }
    if ($Name -eq 'request' -and $Value.Contains('statusCode') -and $null -ne $Value['statusCode']) {
        if (-not (Test-BowerInteger -Value $Value['statusCode'] -Minimum 100 -Maximum 599)) {
            'request.statusCode must be an integer between 100 and 599.'
        }
    }
}

function Test-BowerInteger {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object] $Value,

        [long] $Minimum,

        [long] $Maximum
    )

    ($Value -is [int] -or $Value -is [long] -or $Value -is [short] -or $Value -is [byte]) -and
    ([long]$Value -ge $Minimum) -and ([long]$Value -le $Maximum)
}

function Get-BowerSecurityEventProblem {
    <# Returns every schema problem for an envelope dictionary (empty when valid). #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object] $Envelope
    )

    if ($Envelope -isnot [System.Collections.IDictionary]) {
        'The security event must be an object.'
        return
    }

    Get-BowerUnknownPropertyProblem -Path 'Event' -Data $Envelope -Allowed $script:EnvelopeProperties
    foreach ($name in $script:EnvelopeRequired) {
        if (-not $Envelope.Contains($name) -or $null -eq $Envelope[$name]) {
            "$name is required."
        }
    }

    if ($Envelope.Contains('schemaVersion') -and $null -ne $Envelope['schemaVersion'] -and $Envelope['schemaVersion'] -cne $script:EnvelopeSchemaVersion) {
        "schemaVersion must be '$($script:EnvelopeSchemaVersion)'."
    }
    if ($Envelope.Contains('eventId') -and $null -ne $Envelope['eventId']) {
        Get-BowerStringProblem -Path 'eventId' -Value $Envelope['eventId'] -MinimumLength 1 -MaximumLength 128
    }
    if ($Envelope.Contains('eventOriginalId')) {
        Get-BowerStringProblem -Path 'eventOriginalId' -Value $Envelope['eventOriginalId'] -MaximumLength 256 -AllowNull
    }
    if ($Envelope.Contains('timeGenerated') -and $null -ne $Envelope['timeGenerated'] -and -not (Test-BowerDateTimeString -Value $Envelope['timeGenerated'])) {
        'timeGenerated must be an RFC 3339 date-time with an offset.'
    }
    if ($Envelope.Contains('timeObserved') -and $null -ne $Envelope['timeObserved'] -and -not (Test-BowerDateTimeString -Value $Envelope['timeObserved'])) {
        'timeObserved must be an RFC 3339 date-time with an offset.'
    }
    if ($Envelope.Contains('eventCategory') -and $null -ne $Envelope['eventCategory'] -and $script:EventCategories -cnotcontains $Envelope['eventCategory']) {
        "eventCategory must be one of: $($script:EventCategories -join ', ')."
    }
    if ($Envelope.Contains('eventType') -and $null -ne $Envelope['eventType'] -and -not ($Envelope['eventType'] -is [string] -and $Envelope['eventType'] -cmatch $script:EventTypePattern)) {
        'eventType must match ^[a-z][a-z0-9_]{2,127}$ (lowercase letters, digits and underscores).'
    }
    if ($Envelope.Contains('eventAction') -and $null -ne $Envelope['eventAction']) {
        Get-BowerStringProblem -Path 'eventAction' -Value $Envelope['eventAction'] -MinimumLength 1 -MaximumLength 128
    }
    if ($Envelope.Contains('eventResult') -and $null -ne $Envelope['eventResult'] -and $script:EventResults -cnotcontains $Envelope['eventResult']) {
        "eventResult must be one of: $($script:EventResults -join ', ')."
    }
    if ($Envelope.Contains('eventSeverity') -and $script:EventSeverities -cnotcontains $Envelope['eventSeverity']) {
        "eventSeverity must be one of: $($script:EventSeverities -join ', ')."
    }
    if ($Envelope.Contains('eventOutcomeReason')) {
        Get-BowerStringProblem -Path 'eventOutcomeReason' -Value $Envelope['eventOutcomeReason'] -MaximumLength 1024 -AllowNull
    }

    Get-BowerNestedProblem -Name 'application' -Value $Envelope['application']
    foreach ($name in 'actor', 'target', 'source', 'request') {
        if ($Envelope.Contains($name)) {
            Get-BowerNestedProblem -Name $name -Value $Envelope[$name]
        }
    }
    foreach ($name in 'change', 'security', 'collector', 'labels', 'attributes') {
        if ($Envelope.Contains($name) -and $null -ne $Envelope[$name] -and $Envelope[$name] -isnot [System.Collections.IDictionary]) {
            "$name must be an object."
        }
    }
    foreach ($name in 'labels', 'attributes') {
        if ($Envelope[$name] -is [System.Collections.IDictionary] -and $Envelope[$name].Count -gt 64) {
            "$name may contain at most 64 properties."
        }
    }
    if ($Envelope['labels'] -is [System.Collections.IDictionary]) {
        foreach ($key in $Envelope['labels'].Keys) {
            Get-BowerStringProblem -Path "labels.$key" -Value $Envelope['labels'][$key] -MaximumLength 256
        }
    }
}

function ConvertTo-BowerEventJson {
    <#
    Normalises and validates one event, returning { EventId; Json; Bytes }. Throws an
    ArgumentException listing every problem when the envelope is invalid or too large.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object] $InputObject
    )

    $envelope = if ($InputObject -is [string]) {
        try {
            ConvertTo-BowerEnvelopeData -InputObject ($InputObject | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
        }
        catch {
            throw [System.ArgumentException]::new('The security event string is not valid JSON.')
        }
    }
    else {
        ConvertTo-BowerEnvelopeData -InputObject $InputObject
    }

    $problems = @(Get-BowerSecurityEventProblem -Envelope $envelope)
    if ($problems.Count -gt 0) {
        $identifier = if ($envelope -is [System.Collections.IDictionary] -and $envelope['eventId'] -is [string]) { " '$($envelope['eventId'])'" } else { '' }
        throw [System.ArgumentException]::new("Security event$identifier is invalid: $($problems -join ' ')")
    }

    $json = $envelope | ConvertTo-Json -Depth 32 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt $script:MaximumEventBytes) {
        throw [System.ArgumentException]::new(
            "Security event '$($envelope['eventId'])' is $($bytes.Length) bytes; the collector accepts at most $($script:MaximumEventBytes) bytes.")
    }

    [pscustomobject]@{
        EventId = [string]$envelope['eventId']
        Json    = $json
        Bytes   = $bytes
    }
}
