using System.Net;

namespace Bower.Sdk;

public sealed record AuthenticationFailedEvent
{
    public string? UserId { get; init; }

    public required string Username { get; init; }

    public IPAddress? SourceIpAddress { get; init; }

    public required string FailureReason { get; init; }

    public required string CorrelationId { get; init; }

    public string? OriginalEventId { get; init; }
}

public sealed record RoleMembershipChangedEvent
{
    public required string ActorUserId { get; init; }

    public required string TargetUserId { get; init; }

    public required string Role { get; init; }

    public required MembershipChange Change { get; init; }

    public string? Reason { get; init; }

    public required string CorrelationId { get; init; }
}

public sealed record SensitiveDataExportedEvent
{
    public required string ActorUserId { get; init; }

    public required long RecordCount { get; init; }

    public required string ExportFormat { get; init; }

    public required string DataClassification { get; init; }

    public required string ExportId { get; init; }

    public required string CorrelationId { get; init; }
}

public enum MembershipChange
{
    Added,
    Removed
}
