using Bower.Integrity;

namespace Bower.Management.Api;

/// <summary>Review state of a submitted, immutable privacy profile version.</summary>
public enum PrivacyProfileVersionStatus
{
    PendingReview,
    Approved,
    Rejected
}

/// <summary>Body of <c>POST /privacy-profiles/validate</c>.</summary>
public sealed record PrivacyProfileContentRequest(string Content);

/// <summary>Body of <c>POST /privacy-profiles/preview</c>: profile YAML and a JSON sample.</summary>
public sealed record PrivacyProfilePreviewRequest(string Content, string Sample);

/// <summary>Body of <c>POST /privacy-profiles</c>.</summary>
public sealed record PrivacyProfileSubmission(string Content, string ChangeSummary);

/// <summary>Body of <c>POST /collectors/{id}/privacy-profile</c>.</summary>
public sealed record PrivacyProfileAssignmentRequest(string VersionId, string Reason);

/// <summary>Metadata of one custom detector (never its samples).</summary>
public sealed record PrivacyProfileCustomDetectorSummary(string Id, string? Description, string Action);

/// <summary>Validation verdict and a metadata-only summary of a privacy profile.</summary>
public sealed record PrivacyProfileValidation(
    bool Valid,
    IReadOnlyList<string> Errors,
    string? ProfileId,
    string? Version,
    string? ContentHash,
    IReadOnlyList<PrivacyProfileCustomDetectorSummary> CustomDetectors,
    int SecretFieldNames,
    int DetectorOverrides,
    int FieldRules);

/// <summary>One detector or field rule applied during a preview.</summary>
public sealed record PrivacyProfilePreviewFinding(string DetectorId, string Action, string Path);

/// <summary>Result of redacting a sample with a candidate profile. Never persisted or logged.</summary>
public sealed record PrivacyProfilePreview(
    bool Valid,
    IReadOnlyList<string> Errors,
    string? Redacted,
    IReadOnlyList<PrivacyProfilePreviewFinding> Findings);

public sealed record PrivacyProfileVersionSummary(
    string Id,
    string ProfileId,
    string Version,
    string? Description,
    string ContentHash,
    string ChangeSummary,
    PrivacyProfileVersionStatus Status,
    string? AuthorName,
    DateTimeOffset CreatedAt,
    string? ReviewerName,
    DateTimeOffset? ReviewedAt,
    string? ReviewReason,
    int AssignedCollectors);

/// <summary>Summary fields plus the content, author object id and the previous approved version.</summary>
public sealed record PrivacyProfileVersionDetail(
    string Id,
    string ProfileId,
    string Version,
    string? Description,
    string ContentHash,
    string ChangeSummary,
    PrivacyProfileVersionStatus Status,
    string? AuthorName,
    DateTimeOffset CreatedAt,
    string? ReviewerName,
    DateTimeOffset? ReviewedAt,
    string? ReviewReason,
    int AssignedCollectors,
    string Content,
    string AuthorObjectId,
    string? PreviousApprovedVersionId);

/// <summary>One assignment history row: <c>assigned</c> or <c>cleared</c>.</summary>
public sealed record PrivacyProfileAssignment(
    long Id,
    string CollectorId,
    string? VersionId,
    string? ProfileId,
    string? Version,
    string Action,
    string Reason,
    string? ActorName,
    DateTimeOffset OccurredAt);

/// <summary>The approved privacy profile version a collector is expected to run.</summary>
public sealed record DesiredPrivacyProfile(
    string VersionId,
    string ProfileId,
    string Version,
    string ContentHash);

/// <summary>
/// Signed deployment document served to a collector. The signature covers the canonical
/// JSON of every field except <see cref="Signature"/> (see <see cref="ManagedPrivacyProfileSigner"/>).
/// </summary>
public sealed record ManagedPrivacyProfile(
    string CollectorId,
    string VersionId,
    string ProfileId,
    string Version,
    string ContentHash,
    string Content,
    string IssuedAt,
    DetachedSignature Signature);
