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
    long? DeadLettered = null,
    string? PrivacyProfileHash = null,
    int? SchemaVersion = null,
    int? HeartbeatIntervalSeconds = null,
    long? OldestUndeliveredAgeSeconds = null,
    DateTimeOffset? LastSuccessfulDeliveryAt = null,
    CanaryReport? LastCanary = null,
    IReadOnlyList<string>? CommandCapabilities = null,
    IReadOnlyList<CommandResultReport>? CommandResults = null)
{
    /// <summary>A body without schemaVersion is a v1 heartbeat.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsV2 => SchemaVersion >= 2;
}

/// <summary>The last management canary a collector ran. <c>queued</c> is local admission, never Sentinel proof.</summary>
public sealed record CanaryReport(string CommandId, string? EventId, DateTimeOffset RanAt, string Outcome);

/// <summary>A command result reported on a v2 heartbeat. Metadata only.</summary>
public sealed record CommandResultReport(string? CommandId, string Status, string Code, DateTimeOffset CompletedAt);

/// <summary>
/// Heartbeat v2 response: signed commands for this collector and the result ids management
/// recorded (the collector drops those). v1 heartbeats still receive the collector record.
/// </summary>
public sealed record HeartbeatResponse(
    int SchemaVersion,
    string CollectorId,
    CollectorStatus Status,
    IReadOnlyList<SignedCollectorCommand> Commands,
    IReadOnlyList<string> AcknowledgedResults);

/// <summary>A command signed by management, bound to one collector, a nonce and an expiry.</summary>
public sealed record SignedCollectorCommand(
    string Kind,
    string CommandId,
    string CollectorId,
    string Command,
    string Nonce,
    string IssuedAt,
    string ExpiresAt,
    Bower.Integrity.DetachedSignature Signature);

/// <summary>Issue one command from the closed set. Lifetime 1–60 minutes (default 15).</summary>
public sealed record CollectorCommandRequest(string? Command, string Reason, int? ExpiresInMinutes = null);

/// <summary>
/// A command's lifecycle: <c>pending</c>, <c>delivered</c>, then <c>succeeded</c>,
/// <c>failed</c>, <c>rejected</c> (by the collector) or <c>expired</c> (no result in time).
/// </summary>
public sealed record CollectorCommandRecord(
    string Id,
    string CollectorId,
    string Command,
    string Status,
    string Reason,
    string ActorObjectId,
    string ActorName,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? DeliveredAt,
    DateTimeOffset? CompletedAt,
    string? ResultCode);

/// <summary>Per-collector source counts. <c>pending</c> sources are not yet due, so neither healthy nor degraded.</summary>
public sealed record SourceHealthSummary(int Total, int Healthy, int Pending, int Degraded);

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
    long DeadLettered = 0,
    DesiredPrivacyProfile? DesiredPrivacyProfile = null,
    string? ReportedPrivacyProfileHash = null,
    int HeartbeatSchemaVersion = 1,
    int? HeartbeatIntervalSeconds = null,
    long? OldestUndeliveredAgeSeconds = null,
    DateTimeOffset? LastSuccessfulDeliveryAt = null,
    CanaryReport? LastCanary = null,
    IReadOnlyList<string>? CommandCapabilities = null,
    DateTimeOffset? DeliveryFailingSince = null)
{
    /// <summary>
    /// Query-time connectivity (see <see cref="CollectorConnectivity"/>); set by the read
    /// endpoints, null when not evaluated.
    /// </summary>
    public string? Connectivity { get; init; }

    /// <summary>Source counts from the per-source report of the last heartbeat.</summary>
    public SourceHealthSummary SourceSummary => new(
        Sources.Count,
        Sources.Count(source => string.Equals(source.Status, "healthy", StringComparison.OrdinalIgnoreCase)),
        Sources.Count(source => string.Equals(source.Status, "pending", StringComparison.OrdinalIgnoreCase)),
        Sources.Count(source => !string.Equals(source.Status, "healthy", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(source.Status, "pending", StringComparison.OrdinalIgnoreCase)));

    /// <summary>Null when no policy is assigned; otherwise whether the collector runs it.</summary>
    public bool? PolicyInSync => DesiredPolicyHash is null
        ? null
        : string.Equals(DesiredPolicyHash, PolicyHash, StringComparison.Ordinal);

    /// <summary>
    /// Null when no privacy profile version is assigned; otherwise whether the collector's
    /// last heartbeat reported the assigned version's content hash.
    /// </summary>
    public bool? PrivacyProfileInSync => DesiredPrivacyProfile is null
        ? null
        : string.Equals(DesiredPrivacyProfile.ContentHash, ReportedPrivacyProfileHash, StringComparison.Ordinal);
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
    DateTimeOffset OccurredAt,
    string? InitiatedByObjectId = null,
    string? InitiatedByName = null);

/// <summary>
/// Fleet posture at query time. A collector is eligible when it is Active and its last
/// heartbeat is fresh. <see cref="SourcesReporting"/> counts healthy sources of eligible
/// collectors; <see cref="SourcesDegraded"/> counts every other source, so reporting plus
/// degraded stays the whole denominator. <see cref="SourcesUnknown"/> is the part of
/// <see cref="SourcesDegraded"/> without evidence either way: every source of a collector
/// that is stale or not Active, and <c>pending</c> sources (not yet seen, still inside
/// their allowance) of eligible collectors. <see cref="PrivacyProfileDrift"/> counts every
/// eligible drifting collector; <see cref="PrivacyProfileExceptions"/> holds at most 12 and
/// omits any whose latest assignment history row does not assign the version held.
/// </summary>
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
    long DeadLettered = 0,
    int PrivacyProfileDrift = 0,
    IReadOnlyList<PrivacyProfileDriftRecord>? PrivacyProfileExceptions = null,
    int SourcesUnknown = 0);

/// <summary>
/// An assigned privacy profile version that a fresh heartbeat did not confirm: the desired
/// assignment (revision, version and content hash) against the hash the collector reported
/// and when. Metadata only: never profile content or key material.
/// </summary>
public sealed record PrivacyProfileDriftRecord(
    string CollectorId,
    string MachineName,
    long AssignmentRevision,
    DateTimeOffset AssignedAt,
    string VersionId,
    string ProfileId,
    string Version,
    string AssignedHash,
    string? ObservedHash,
    DateTimeOffset ObservedAt)
{
    /// <summary>
    /// The collector's heartbeat and privacy-profile deployment jobs each run every minute,
    /// independently: one poll interval plus margin before a reported hash counts as a
    /// rejected rollout rather than one not yet fetched.
    /// </summary>
    public static readonly TimeSpan ConfirmationDelay = TimeSpan.FromMinutes(2);

    /// <summary>
    /// True when the observing heartbeat arrived at least <see cref="ConfirmationDelay"/>
    /// after the assignment, so the collector had the chance to apply it; false while it is
    /// still awaiting a heartbeat that could confirm the assignment.
    /// </summary>
    public bool MismatchConfirmed => ObservedAt >= AssignedAt + ConfirmationDelay;
}

public sealed record CurrentAccess(
    string ObjectId,
    string DisplayName,
    IReadOnlyList<string> Roles,
    bool DevelopmentAuthentication);
