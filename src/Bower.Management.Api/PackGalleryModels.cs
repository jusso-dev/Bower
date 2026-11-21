namespace Bower.Management.Api;

public static class PackInstallRequestStatus
{
    public const string PendingReview = "pending-review";
    public const string Approved = "approved";
    public const string Rejected = "rejected";
}

/// <summary>Gallery listing of signed packs held by management. Metadata and post-redaction checks only.</summary>
public sealed record PackGalleryResponse(
    bool Configured,
    int TrustedKeyCount,
    IReadOnlyList<PackGalleryItem> Packs,
    IReadOnlyList<PackTargetGroup> Groups);

/// <summary>A collector group (environment) eligible for pack installation.</summary>
public sealed record PackTargetGroup(
    string Environment,
    int EligibleCollectors,
    IReadOnlyList<string> CollectorIds);

/// <summary>
/// One pack archive in the management gallery. Untrusted or tampered archives are returned with
/// <see cref="Trusted"/> = false and a plain refusal reason so operators see why they were refused.
/// </summary>
public sealed record PackGalleryItem(
    bool Trusted,
    string FileName,
    string? Id,
    string? Version,
    string? Name,
    string? Description,
    string? Owner,
    DateTimeOffset? BuiltAtUtc,
    string? PackHash,
    string? SignedByKeyId,
    IReadOnlyList<string> EventTypes,
    IReadOnlyList<PackPolicySummary> Policies,
    IReadOnlyList<string> Redactions,
    int DetectionCount,
    int ParserCount,
    IReadOnlyList<PackSampleSummary> SampleResults,
    string? RefusalReason);

public sealed record PackPolicySummary(
    string Id,
    string Version,
    string Action,
    IReadOnlyList<string> EventTypes,
    string Hash);

/// <summary>Metadata-only sample execution result: never raw sample inputs or sensitive values.</summary>
public sealed record PackSampleSummary(
    string Name,
    bool Passed,
    string ExpectedDecision,
    string ActualDecision,
    IReadOnlyList<string> Problems);

/// <summary>Request to install a signed pack to a collector group (environment) or single collector.</summary>
public sealed record PackInstallSubmission(
    string? PackId,
    string? Version,
    string? TargetEnvironment,
    string? TargetCollectorId,
    string? Reason);

/// <summary>Population diff snapshot computed when submitting or reviewing a pack install.</summary>
public sealed record PackPopulationDiff(
    string PackId,
    string PackVersion,
    string PackHash,
    IReadOnlyList<string> EventTypesAdded,
    IReadOnlyList<PackPolicyDiffEntry> PolicyChanges,
    IReadOnlyList<PackCollectorDiffEntry> AffectedCollectors);

public sealed record PackPolicyDiffEntry(
    string PolicyId,
    string Change,
    string Detail);

public sealed record PackCollectorDiffEntry(
    string CollectorId,
    string MachineName,
    string Environment,
    string CurrentPolicyHash,
    string? CurrentDesiredPolicyHash,
    string TargetPolicyHash,
    bool AlreadyAssigned);

/// <summary>Stored four-eyes pack installation request.</summary>
public sealed record PackInstallRequestRecord(
    string Id,
    string PackId,
    string PackVersion,
    string PackName,
    string PackHash,
    string SignedByKeyId,
    string? TargetEnvironment,
    string? TargetCollectorId,
    string Status,
    PackPopulationDiff Diff,
    string Reason,
    string RequestedByObjectId,
    string RequestedByName,
    DateTimeOffset RequestedAt,
    string? ReviewerName,
    DateTimeOffset? ReviewedAt,
    string? ReviewReason);
