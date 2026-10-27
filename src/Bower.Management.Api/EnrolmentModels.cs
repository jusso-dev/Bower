namespace Bower.Management.Api;

/// <summary>Create a one-time enrolment token. Lifetime 1–168 hours (default 24).</summary>
public sealed record EnrolmentTokenRequest(
    string Environment,
    string Reason,
    string? CollectorId = null,
    int? ExpiresInHours = null);

/// <summary>Enrolment token metadata. Never the token or its hash.</summary>
public sealed record EnrolmentTokenRecord(
    string Id,
    string Environment,
    string? CollectorId,
    string Status,
    string Reason,
    string CreatedByObjectId,
    string CreatedByName,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? UsedAt,
    string? UsedByCollectorId,
    DateTimeOffset? RevokedAt);

/// <summary>The only response that carries the token. The console shows it once.</summary>
public sealed record IssuedEnrolmentToken(string Token, EnrolmentTokenRecord Record);

/// <summary>
/// A collector's enrolment: the one-time token, its inventory and the P-256 public key it
/// generated (SPKI PEM). The private key never leaves the collector.
/// </summary>
public sealed record CollectorEnrolmentRequest(
    string Token,
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    string PublicKey);

/// <summary>Rotation: the collector's new public key, sent under its current credential.</summary>
public sealed record CollectorCredentialRotationRequest(string PublicKey);

/// <summary>A credential issued at enrolment or rotation. Metadata only: no secret exists to return.</summary>
public sealed record IssuedCollectorCredential(
    string CollectorId,
    string CredentialId,
    CollectorStatus Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

/// <summary>Collector credential metadata. <c>origin</c> is <c>enrolment</c> or <c>rotation</c>.</summary>
public sealed record CollectorCredentialRecord(
    string Id,
    string CollectorId,
    string Status,
    string Origin,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? EndedAt);

/// <summary>An enrolment outcome: the issued credential, or the refusal code (audited).</summary>
public sealed record EnrolmentResult(IssuedCollectorCredential? Credential, string? Refusal);
