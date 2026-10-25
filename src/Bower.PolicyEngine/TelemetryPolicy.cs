namespace Bower.PolicyEngine;

public sealed record TelemetryPolicy
{
    public required string ApiVersion { get; init; }

    public required string Kind { get; init; }

    public required PolicyMetadata Metadata { get; init; }

    public required PolicyMatch Match { get; init; }

    public required PolicyRequirements Requirements { get; init; }

    public required PolicyAction Decision { get; init; }

    public PolicyRouting? Routing { get; init; }

    /// <summary>
    /// Optional per-key cap on accepted events. Omitted from the hash input when absent so
    /// existing policy hashes are unchanged.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public PolicySuppression? Suppression { get; init; }
}

public sealed record PolicyMetadata
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Version { get; init; }

    public required string Owner { get; init; }

    public DateOnly? ReviewDate { get; init; }
}

public sealed record PolicyMatch
{
    public List<string> EventCategories { get; init; } = [];

    public List<string> EventTypes { get; init; } = [];

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? EventActions { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? EventResults { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? EventSeverities { get; init; }
}

public sealed record PolicyRequirements
{
    public List<string> RequiredFields { get; init; } = [];

    public List<string> AtLeastOne { get; init; } = [];

    public List<string> RecommendedFields { get; init; } = [];
}

public sealed record PolicyAction
{
    public required string Action { get; init; }

    public int MinimumValueScore { get; init; }

    public bool NeverSample { get; init; }
}

public sealed record PolicyRouting
{
    public string? Profile { get; init; }

    public string? Destination { get; init; }
}

/// <summary>
/// Admits at most <see cref="AllowPerWindow"/> accepted events per key in each fixed,
/// epoch-aligned window of <see cref="WindowSeconds"/>. Later events are counted durably
/// and reported by one <c>telemetry_aggregation_summary</c> event when the window ends.
/// </summary>
public sealed record PolicySuppression
{
    public List<string> KeyFields { get; init; } = [];

    public int WindowSeconds { get; init; }

    public int AllowPerWindow { get; init; }
}
