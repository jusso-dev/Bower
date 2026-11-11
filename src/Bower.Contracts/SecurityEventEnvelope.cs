using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Contracts;

public sealed record SecurityEventEnvelope
{
    public const string CurrentSchemaVersion = "1.0.0";

    public required string SchemaVersion { get; init; } = CurrentSchemaVersion;

    public required string EventId { get; init; }

    public string? EventOriginalId { get; init; }

    public required DateTimeOffset TimeGenerated { get; init; }

    public DateTimeOffset? TimeObserved { get; init; }

    public required string EventCategory { get; init; }

    public required string EventType { get; init; }

    public required string EventAction { get; init; }

    public required EventResult EventResult { get; init; }

    public EventSeverity EventSeverity { get; init; } = EventSeverity.Medium;

    public string? EventOutcomeReason { get; init; }

    public required ApplicationContext Application { get; init; }

    public ActorContext? Actor { get; init; }

    public TargetContext? Target { get; init; }

    public SourceContext? Source { get; init; }

    public RequestContext? Request { get; init; }

    public ChangeContext? Change { get; init; }

    public SecurityDecisionContext? Security { get; init; }

    public CollectorContext? Collector { get; init; }

    public IReadOnlyDictionary<string, string>? Labels { get; init; }

    public IReadOnlyDictionary<string, JsonElement>? Attributes { get; init; }

    /// <summary>
    /// Sanitisation summary produced by the Privacy &amp; Secret Protection Engine.
    /// Never contains original sensitive values.
    /// </summary>
    public PrivacyContext? Privacy { get; init; }
}

/// <summary>Additive privacy metadata attached after detection and policy application.</summary>
public sealed record PrivacyContext
{
    public required IReadOnlyList<string> Detected { get; init; }

    public required IReadOnlyDictionary<string, string> Actions { get; init; }
}

public sealed record ApplicationContext
{
    public required string Name { get; init; }

    public string? Version { get; init; }

    public required string Environment { get; init; }

    public string? Instance { get; init; }

    public string? TenantId { get; init; }
}

public sealed record ActorContext
{
    public string? UserId { get; init; }

    public string? Username { get; init; }

    public string? DisplayName { get; init; }

    public ActorType Type { get; init; } = ActorType.Human;

    public string? Role { get; init; }
}

public sealed record TargetContext
{
    public required string Type { get; init; }

    public string? Id { get; init; }

    public string? Name { get; init; }
}

public sealed record SourceContext
{
    public string? IpAddress { get; init; }

    public string? Hostname { get; init; }

    public int? Port { get; init; }
}

public sealed record RequestContext
{
    public string? CorrelationId { get; init; }

    public string? TraceId { get; init; }

    public string? SessionId { get; init; }

    public string? Method { get; init; }

    public string? Path { get; init; }

    public int? StatusCode { get; init; }
}

public sealed record ChangeContext
{
    public string? Field { get; init; }

    public string? PreviousValue { get; init; }

    public string? NewValue { get; init; }
}

public sealed record SecurityDecisionContext
{
    public required string PolicyId { get; init; }

    public required string PolicyVersion { get; init; }

    public required int ValueScore { get; init; }

    public required DecisionAction Decision { get; init; }

    public required IReadOnlyList<string> ClassificationReasons { get; init; }

    public required string PolicyHash { get; init; }
}

public sealed record CollectorContext
{
    public required string Id { get; init; }

    public required string Version { get; init; }

    public required string SourceAdapter { get; init; }

    public required string ConfigurationHash { get; init; }

    public string? BatchId { get; init; }

    public required DateTimeOffset ReceivedAt { get; init; }

    /// <summary>
    /// Where the event entered Bower, recorded by Bower, never by the producer: the processor
    /// rebuilds <see cref="CollectorContext"/> on every event, so a producer cannot set it.
    /// Stored in the table's <c>Origin</c> column.
    /// </summary>
    public EventOrigin? Origin { get; init; }
}

/// <summary>
/// The path an event took into Bower, for tracing a row to the system that wrote it (#228, #253).
/// <see cref="Kind"/> is <c>cloudwatch-logs</c> (set by the collector from the trusted cloud
/// forwarder) or <c>ama-syslog</c> (set by the collection rule from the agent's host).
/// </summary>
public sealed record EventOrigin
{
    public required string Kind { get; init; }

    /// <summary>The machine Azure Monitor Agent recorded (ama-syslog).</summary>
    public string? Host { get; init; }

    /// <summary>The CloudWatch Logs log group (cloudwatch-logs).</summary>
    public string? LogGroup { get; init; }

    /// <summary>The CloudWatch Logs log stream, for example the instance ID (cloudwatch-logs).</summary>
    public string? LogStream { get; init; }
}

[JsonConverter(typeof(DefinedEnumConverter<EventResult>))]
public enum EventResult
{
    Unknown,
    Success,
    Failure,
    Denied
}

[JsonConverter(typeof(DefinedEnumConverter<EventSeverity>))]
public enum EventSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

[JsonConverter(typeof(DefinedEnumConverter<ActorType>))]
public enum ActorType
{
    Human,
    Service,
    Machine,
    System,
    Unknown
}

[JsonConverter(typeof(DefinedEnumConverter<DecisionAction>))]
public enum DecisionAction
{
    Accept,
    Reject,
    Sample,
    Aggregate,
    RedactAndAccept,
    Quarantine,
    DeadLetter
}
