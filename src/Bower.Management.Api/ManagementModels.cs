using Bower.Jobs;

namespace Bower.Management.Api;

public static class BowerRoles
{
    public const string Viewer = "Bower.Viewer";
    public const string Operator = "Bower.Operator";
    public const string Approver = "Bower.Approver";
    public const string Administrator = "Bower.Administrator";
    public const string Collector = "Bower.Collector";

    public static readonly string[] Interactive =
        [Viewer, Operator, Approver, Administrator];
}

public enum CollectorStatus
{
    Pending,
    Approved,
    Active,
    Suspended,
    Revoked
}

public sealed record SourceReport(
    string Id,
    string Type,
    string Status,
    long? LagSeconds,
    DateTimeOffset? LastEventAt);

public sealed record OutputReport(
    string Id,
    string Type,
    string Status,
    DateTimeOffset? LastAcknowledgedAt,
    string? LastErrorCode);

public sealed record CollectorRegistration(
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs);

public sealed record CollectorHeartbeat(
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    long QueueDepth,
    string DeliveryStatus,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs,
    IReadOnlyList<BackgroundJobStatus>? Jobs = null,
    LedgerReport? Ledger = null,
    long? DeadLettered = null);

/// <summary>Collector queue ledger head: management keeps the last one as a witness.</summary>
public sealed record LedgerReport(long Sequence, string Hash);

public sealed record DesiredPolicyRequest(string? PolicyHash, string Reason);

public sealed record CollectorRecord(
    string Id,
    string MachineName,
    string Environment,
    string Version,
    CollectorStatus Status,
    string PrincipalObjectId,
    DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt,
    string ConfigurationHash,
    string PolicyHash,
    long QueueDepth,
    string DeliveryStatus,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs,
    IReadOnlyList<BackgroundJobStatus>? Jobs = null,
    string? DesiredPolicyHash = null,
    long? LedgerSequence = null,
    long DeadLettered = 0)
{
    /// <summary>Null when no policy is assigned; otherwise whether the collector runs it.</summary>
    public bool? PolicyInSync => DesiredPolicyHash is null
        ? null
        : string.Equals(DesiredPolicyHash, PolicyHash, StringComparison.Ordinal);
}

public sealed record ApprovalRequest(string Reason);

public sealed record ApprovalRecord(
    string Id,
    string CollectorId,
    string Action,
    string Reason,
    string ActorObjectId,
    string ActorName,
    DateTimeOffset OccurredAt);

public sealed record AuditRecord(
    string Id,
    string Action,
    string TargetType,
    string TargetId,
    string ActorObjectId,
    string ActorName,
    DateTimeOffset OccurredAt);

public sealed record OverviewRecord(
    int TotalCollectors,
    int PendingApproval,
    int UnhealthyCollectors,
    int StaleCollectors,
    long TotalQueueDepth,
    int SourcesReporting,
    int SourcesDegraded,
    IReadOnlyList<CollectorRecord> Exceptions,
    int PolicyDrift = 0,
    long DeadLettered = 0);

public sealed record CurrentAccess(
    string ObjectId,
    string DisplayName,
    IReadOnlyList<string> Roles,
    bool DevelopmentAuthentication);
