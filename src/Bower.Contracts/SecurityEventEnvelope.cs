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
}

[JsonConverter(typeof(JsonStringEnumConverter<EventResult>))]
public enum EventResult
{
    Unknown,
    Success,
    Failure,
    Denied
}

[JsonConverter(typeof(JsonStringEnumConverter<EventSeverity>))]
public enum EventSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

[JsonConverter(typeof(JsonStringEnumConverter<ActorType>))]
public enum ActorType
{
    Human,
    Service,
    Machine,
    System,
    Unknown
}

[JsonConverter(typeof(JsonStringEnumConverter<DecisionAction>))]
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
