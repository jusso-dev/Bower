function New-BowerSecurityEvent {
    <#
    .SYNOPSIS
    Creates a Bower security event envelope (schema 1.0.0).

    .DESCRIPTION
    Builds an in-memory event that matches schemas/envelope/security-event.schema.json and
    validates it before returning. Required fields are enforced and the event is rejected
    if any field breaks the schema (unknown nested properties, lengths, enumerations,
    event type format, timestamps). Nothing is sent; pipe the result to
    Send-BowerSecurityEvent.

    Only include data that the event needs. The collector still applies the privacy
    profile before persistence, but semantic events should not carry raw payloads,
    tokens or secrets.

    .PARAMETER EventCategory
    Event category, for example authentication or administrative-activity.

    .PARAMETER EventType
    Lowercase event type (^[a-z][a-z0-9_]{2,127}$), for example user_sign_in.

    .PARAMETER EventAction
    Action that occurred, 1-128 characters.

    .PARAMETER EventResult
    unknown, success, failure or denied.

    .PARAMETER ApplicationName
    Producing application name.

    .PARAMETER ApplicationEnvironment
    Environment such as production or test.

    .PARAMETER ApplicationVersion
    Application version, at most 64 characters.

    .PARAMETER ApplicationInstance
    Application instance (host, pod or deployment slot), at most 256 characters.

    .PARAMETER ApplicationTenantId
    Application tenant identifier, at most 256 characters (classified personal).

    .PARAMETER EventId
    Globally unique, retry-stable identifier. Defaults to a new GUID. Reuse the same ID
    when retrying the same upstream event.

    .PARAMETER TimeGenerated
    When the event occurred. Defaults to now (UTC).

    .PARAMETER EventOriginalId
    Identifier of the event in the source system, at most 256 characters.

    .PARAMETER TimeObserved
    When the producer observed the event, if different from TimeGenerated.

    .PARAMETER EventSeverity
    informational, low, medium, high or critical.

    .PARAMETER EventOutcomeReason
    Short outcome reason, at most 1024 characters. Never include secrets or raw payloads.

    .PARAMETER Actor
    Hashtable with userId, username, displayName, type (human, service, machine, system,
    unknown) and role.

    .PARAMETER Target
    Hashtable with type (required), id and name.

    .PARAMETER Source
    Hashtable with ipAddress, hostname and port.

    .PARAMETER Request
    Hashtable with correlationId, traceId, sessionId, method, path and statusCode.

    .PARAMETER Change
    Object describing a configuration or data change.

    .PARAMETER Security
    Object with security context (for example MFA or risk signals).

    .PARAMETER Labels
    Up to 64 string labels (values at most 256 characters).

    .PARAMETER Attributes
    Up to 64 additional attributes.

    .EXAMPLE
    New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction sign-in `
        -EventResult failure -ApplicationName payroll -ApplicationEnvironment production `
        -Actor @{ userId = 'u-123'; type = 'human' } -EventSeverity medium

    Creates a failed sign-in event.

    .EXAMPLE
    $event = New-BowerSecurityEvent -EventCategory administrative-activity -EventType role_assigned `
        -EventAction assign -EventResult success -ApplicationName portal -ApplicationEnvironment test `
        -Target @{ type = 'role'; id = 'admin' } -EventId 'portal-audit-981'
    $event | Send-BowerSecurityEvent -Token (Get-Secret bower-ingest)

    Creates an event with a stable upstream ID and sends it to the local collector.

    .OUTPUTS
    Bower.SecurityEvent
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    [OutputType('Bower.SecurityEvent')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('authentication', 'authorisation', 'identity-management', 'administrative-activity', 'data-access', 'application-security', 'api-security', 'collector-health')]
        [string] $EventCategory,

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -cmatch '^[a-z][a-z0-9_]{2,127}$' }, ErrorMessage = 'EventType must match ^[a-z][a-z0-9_]{{2,127}}$.')]
        [string] $EventType,

        [Parameter(Mandatory)]
        [ValidateLength(1, 128)]
        [string] $EventAction,

        [Parameter(Mandatory)]
        [ValidateSet('unknown', 'success', 'failure', 'denied')]
        [string] $EventResult,

        [Parameter(Mandatory)]
        [ValidateLength(1, 128)]
        [string] $ApplicationName,

        [Parameter(Mandatory)]
        [ValidateLength(1, 64)]
        [string] $ApplicationEnvironment,

        [ValidateLength(0, 64)]
        [string] $ApplicationVersion,

        [ValidateLength(0, 256)]
        [string] $ApplicationInstance,

        [ValidateLength(0, 256)]
        [string] $ApplicationTenantId,

        [ValidateLength(1, 128)]
        [string] $EventId = [guid]::NewGuid().ToString(),

        [ValidateLength(0, 256)]
        [string] $EventOriginalId,

        [datetimeoffset] $TimeGenerated = [datetimeoffset]::UtcNow,

        [Nullable[datetimeoffset]] $TimeObserved,

        [ValidateSet('informational', 'low', 'medium', 'high', 'critical')]
        [string] $EventSeverity,

        [ValidateLength(0, 1024)]
        [string] $EventOutcomeReason,

        [System.Collections.IDictionary] $Actor,

        [System.Collections.IDictionary] $Target,

        [System.Collections.IDictionary] $Source,

        [System.Collections.IDictionary] $Request,

        [System.Collections.IDictionary] $Change,

        [System.Collections.IDictionary] $Security,

        [System.Collections.IDictionary] $Labels,

        [System.Collections.IDictionary] $Attributes
    )

    $application = [ordered]@{
        name        = $ApplicationName
        environment = $ApplicationEnvironment
    }
    if ($PSBoundParameters.ContainsKey('ApplicationVersion')) { $application.version = $ApplicationVersion }
    if ($PSBoundParameters.ContainsKey('ApplicationInstance')) { $application.instance = $ApplicationInstance }
    if ($PSBoundParameters.ContainsKey('ApplicationTenantId')) { $application.tenantId = $ApplicationTenantId }

    $envelope = [ordered]@{
        schemaVersion = $script:EnvelopeSchemaVersion
        eventId       = $EventId
        timeGenerated = $TimeGenerated.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
        eventCategory = $EventCategory.ToLowerInvariant()
        eventType     = $EventType
        eventAction   = $EventAction
        eventResult   = $EventResult.ToLowerInvariant()
        application   = $application
    }
    if ($PSBoundParameters.ContainsKey('EventOriginalId')) { $envelope.eventOriginalId = $EventOriginalId }
    if ($null -ne $TimeObserved) { $envelope.timeObserved = $TimeObserved.Value.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) }
    if ($EventSeverity) { $envelope.eventSeverity = $EventSeverity.ToLowerInvariant() }
    if ($PSBoundParameters.ContainsKey('EventOutcomeReason')) { $envelope.eventOutcomeReason = $EventOutcomeReason }

    $optional = [ordered]@{
        actor      = $Actor
        target     = $Target
        source     = $Source
        request    = $Request
        change     = $Change
        security   = $Security
        labels     = $Labels
        attributes = $Attributes
    }
    foreach ($name in $optional.Keys) {
        if ($null -ne $optional[$name]) {
            $envelope[$name] = ConvertTo-BowerEnvelopeData -InputObject $optional[$name]
        }
    }

    $problems = @(Get-BowerSecurityEventProblem -Envelope $envelope)
    if ($problems.Count -gt 0) {
        $exception = [System.ArgumentException]::new("Security event is invalid: $($problems -join ' ')")
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new($exception, 'BowerSecurityEventInvalid', 'InvalidArgument', $envelope))
    }

    $result = [pscustomobject]$envelope
    $result.PSObject.TypeNames.Insert(0, 'Bower.SecurityEvent')
    $result
}
