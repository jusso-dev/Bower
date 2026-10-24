using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Bower.Integrity;
using Bower.Redaction.Privacy;

namespace Bower.Collector;

/// <summary>
/// Wire shape of the management API's signed assignment envelope (<c>ManagedPrivacyProfile</c>)
/// and of the cache file <c>profile.json</c>. Field names are the signed contract. Unknown
/// members are rejected: every accepted field is covered by the signature.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[JsonNumberHandling(JsonNumberHandling.Strict)]
internal sealed record ManagedPrivacyProfileDocument(
    string? CollectorId,
    long? AssignmentRevision,
    string? Action,
    string? VersionId,
    string? ProfileId,
    string? Version,
    string? ContentHash,
    string? Content,
    string? IssuedAt,
    DetachedSignature? Signature);

/// <summary>A managed privacy profile that failed verification. Messages are metadata only.</summary>
public sealed class ManagedPrivacyProfileException(string message) : Exception(message);

/// <summary>
/// A signed, collector-bound assignment envelope. <see cref="Action"/> is
/// <c>assigned</c> (with a loader-validated <see cref="Profile"/>) or <c>cleared</c> (the
/// built-in default privacy profile; profile fields are null). <see cref="SignedPayload"/>
/// is the canonical JSON the signature covers, used to compare same-revision documents.
/// </summary>
public sealed record VerifiedManagedPrivacyProfile(
    string Action,
    long AssignmentRevision,
    LoadedPrivacyProfile? Profile,
    string? VersionId,
    string? ProfileId,
    string? Version,
    string? ContentHash,
    byte[] SignedPayload)
{
    public const string Assigned = "assigned";
    public const string Cleared = "cleared";

    public bool IsCleared => Action == Cleared;
}

/// <summary>
/// Verification and the local cache for managed privacy profiles. A document is trusted
/// only when a configured key signed it, it names this collector, and (for an assignment)
/// the loader accepts its content with the collector's real HMAC key and the content hash
/// matches. The cache holds the last verified document, assigned or cleared: it is the
/// assignment-revision high-water mark. Unverified content is never written to disk.
/// </summary>
public static class ManagedPrivacyProfileCache
{
    public const string CacheFileName = "profile.json";

    /// <summary>Upper bound for a deployment document (a 256 KiB profile, JSON-escaped).</summary>
    public const int MaximumDocumentBytes = 1_048_576;

    public static string CachePath(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return Path.Combine(settings.ManagedPrivacyCacheDirectory, CacheFileName);
    }

    public static IReadOnlyList<string> ReadTrustedKeys(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return [.. settings.ManagedPrivacyTrustedKeyFiles.Select(File.ReadAllText)];
    }

    /// <summary>
    /// The verified cached document, or null when there is no cache. Any verification
    /// failure throws with a metadata-only message (start-up fails closed).
    /// </summary>
    public static VerifiedManagedPrivacyProfile? LoadVerified(CollectorSettings settings, byte[]? hmacKey)
    {
        string path = CachePath(settings);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            byte[] document = File.ReadAllBytes(path);
            return Verify(document, settings.CollectorId, ReadTrustedKeys(settings), hmacKey, settings.PrivacyHmacKeyId);
        }
        catch (ManagedPrivacyProfileException exception)
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile cache {path} failed verification: {exception.Message} " +
                "Delete the cache file to fetch the current assignment again.");
        }
    }

    public static VerifiedManagedPrivacyProfile Verify(
        ReadOnlySpan<byte> json,
        string collectorId,
        IReadOnlyList<string> trustedPublicKeyPems,
        byte[]? hmacKey,
        string hmacKeyId)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        if (json.Length > MaximumDocumentBytes)
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is too large.");
        }

        ManagedPrivacyProfileDocument? document;
        try
        {
            document = JsonSerializer.Deserialize(json, CollectorJsonContext.Default.ManagedPrivacyProfileDocument);
        }
        catch (JsonException)
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is not valid JSON.");
        }

        if (document is not
            {
                CollectorId: { } documentCollector,
                AssignmentRevision: { } revision and > 0,
                Action: VerifiedManagedPrivacyProfile.Assigned or VerifiedManagedPrivacyProfile.Cleared,
                IssuedAt: { } issuedAt,
                Signature: { Algorithm: not null, KeyId: not null, Value: not null } signature
            })
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is incomplete.");
        }

        bool assigned = document.Action == VerifiedManagedPrivacyProfile.Assigned;
        bool hasProfileFields = document is { VersionId: not null, ProfileId: not null, Version: not null, ContentHash: not null, Content: not null };
        bool hasAnyProfileField = document.VersionId is not null || document.ProfileId is not null
            || document.Version is not null || document.ContentHash is not null || document.Content is not null;
        if (assigned ? !hasProfileFields : hasAnyProfileField)
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is incomplete.");
        }

        byte[] payload = SignedBytes(
            documentCollector, revision, document.Action, document.VersionId, document.ProfileId,
            document.Version, document.ContentHash, document.Content, issuedAt);
        if (!DetachedSigner.Verify(payload, signature, trustedPublicKeyPems))
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile signature is not trusted.");
        }

        if (!string.Equals(documentCollector, collectorId, StringComparison.Ordinal))
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile was issued for a different collector.");
        }

        if (!assigned)
        {
            return new VerifiedManagedPrivacyProfile(
                VerifiedManagedPrivacyProfile.Cleared, revision, null, null, null, null, null, payload);
        }

        string profileId = document.ProfileId!;
        string version = document.Version!;
        LoadedPrivacyProfile profile;
        try
        {
            profile = PrivacyProfileLoader.Load(document.Content!, hmacKey, hmacKeyId);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or ArgumentException)
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile {profileId}@{version} failed validation: {exception.Message}");
        }

        if (!string.Equals(profile.Hash, document.ContentHash, StringComparison.Ordinal))
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile {profileId}@{version} content hash does not match.");
        }

        if (!string.Equals(profile.Id, profileId, StringComparison.Ordinal)
            || !string.Equals(profile.Version, version, StringComparison.Ordinal))
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile {profileId}@{version} metadata does not match its content.");
        }

        return new VerifiedManagedPrivacyProfile(
            VerifiedManagedPrivacyProfile.Assigned, revision, profile, document.VersionId, profileId, version,
            document.ContentHash, payload);
    }

    /// <summary>
    /// Canonical JSON of exactly the signed fields. Must match the management API's
    /// <c>ManagedPrivacyProfileSigner.SignedBytes</c> byte for byte: <c>assigned</c> signs
    /// collectorId, assignmentRevision, action, versionId, profileId, version, contentHash,
    /// content and issuedAt; <c>cleared</c> signs collectorId, assignmentRevision, action
    /// and issuedAt.
    /// </summary>
    public static byte[] SignedBytes(
        string collectorId,
        long assignmentRevision,
        string action,
        string? versionId,
        string? profileId,
        string? version,
        string? contentHash,
        string? content,
        string issuedAt)
    {
        JsonObject fields = new()
        {
            ["collectorId"] = collectorId,
            ["assignmentRevision"] = assignmentRevision,
            ["action"] = action,
            ["issuedAt"] = issuedAt
        };
        if (action == VerifiedManagedPrivacyProfile.Assigned)
        {
            fields["versionId"] = versionId;
            fields["profileId"] = profileId;
            fields["version"] = version;
            fields["contentHash"] = contentHash;
            fields["content"] = content;
        }

        return CanonicalJson.Bytes(fields);
    }

    /// <summary>
    /// Replaces <paramref name="path"/> atomically: write a temporary file in the same
    /// directory, flush it to disk, then rename over the target. A crash leaves either the
    /// old or the new complete file, never a partial one.
    /// </summary>
    public static void WriteAtomically(string path, ReadOnlySpan<byte> content)
    {
        string directory = Path.GetDirectoryName(Path.GetFullPath(path))
            ?? throw new ArgumentException("Cache path has no directory.", nameof(path));
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (FileStream stream = new(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}

/// <summary>
/// Management mode only: whether the collector has resolved its managed privacy profile and
/// may accept events. Without a verified cache it starts <c>awaiting-first-sync</c> and
/// refuses ingest (HTTP 503) until a sync returns a verified document (staged, restart
/// pending) or 204 (never assigned, so the built-in default is the intended state).
/// <c>BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT=true</c> starts as <c>default-allowed</c> instead.
/// </summary>
public sealed class ManagedPrivacyProfileState
{
    public const string AwaitingFirstSync = "awaiting-first-sync";
    public const string DefaultAllowed = "default-allowed";
    public const string NeverAssigned = "never-assigned";
    public const string Assigned = "assigned";
    public const string Cleared = "cleared";
    public const string RestartPending = "restart-pending";

    /// <summary>Local mode: no managed privacy profile, ingest is never gated.</summary>
    public static ManagedPrivacyProfileState Local { get; } = new();

    private readonly Lock gate = new();
    private string state;
    private long? revision;
    private bool acceptsEvents;

    private ManagedPrivacyProfileState()
    {
        state = "local";
        acceptsEvents = true;
    }

    public ManagedPrivacyProfileState(VerifiedManagedPrivacyProfile? cached, bool allowDefault)
    {
        revision = cached?.AssignmentRevision;
        if (cached is not null)
        {
            state = cached.IsCleared ? Cleared : Assigned;
            acceptsEvents = true;
        }
        else
        {
            state = allowDefault ? DefaultAllowed : AwaitingFirstSync;
            acceptsEvents = allowDefault;
        }
    }

    /// <summary>One of the state constants above, reported in <c>/v1/status</c>.</summary>
    public string State
    {
        get
        {
            lock (gate)
            {
                return state;
            }
        }
    }

    /// <summary>Assignment revision of the verified cached document; null when none.</summary>
    public long? Revision
    {
        get
        {
            lock (gate)
            {
                return revision;
            }
        }
    }

    public bool AcceptsEvents
    {
        get
        {
            lock (gate)
            {
                return acceptsEvents;
            }
        }
    }

    /// <summary>204 without a cache: never assigned, so the running default is intended.</summary>
    public void MarkNeverAssigned()
    {
        lock (gate)
        {
            if (state is AwaitingFirstSync or DefaultAllowed)
            {
                state = NeverAssigned;
                acceptsEvents = true;
            }
        }
    }

    /// <summary>A newer verified document is cached and already matches the running protection.</summary>
    public void MarkResolved(VerifiedManagedPrivacyProfile verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        lock (gate)
        {
            state = verified.IsCleared ? Cleared : Assigned;
            revision = verified.AssignmentRevision;
            acceptsEvents = true;
        }
    }

    /// <summary>
    /// A newer verified document is staged and the host is restarting to apply it. Ingest
    /// stays as it was: a collector awaiting its first sync keeps refusing events.
    /// </summary>
    public void MarkRestartPending(VerifiedManagedPrivacyProfile verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        lock (gate)
        {
            state = RestartPending;
            revision = verified.AssignmentRevision;
        }
    }
}

/// <summary>
/// Refuses ingest with 503 + Retry-After while a management-mode collector has not resolved
/// its managed privacy profile, so no event is enqueued under an unintended profile.
/// </summary>
internal sealed class ManagedPrivacyProfileGateFilter(ManagedPrivacyProfileState state) : IEndpointFilter
{
    public const string RetryAfterSeconds = "30";

    public const string Message =
        "Collector is waiting for its managed privacy profile from management; retry later.";

    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (state.AcceptsEvents)
        {
            return next(context);
        }

        context.HttpContext.Response.Headers.RetryAfter = RetryAfterSeconds;
        return ValueTask.FromResult<object?>(Results.Json(
            new ErrorResponse(Message),
            CollectorJsonContext.Default.ErrorResponse,
            statusCode: StatusCodes.Status503ServiceUnavailable));
    }
}
