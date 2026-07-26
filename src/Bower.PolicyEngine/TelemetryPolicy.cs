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
