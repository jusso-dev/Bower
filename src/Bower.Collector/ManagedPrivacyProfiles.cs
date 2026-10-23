using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Integrity;
using Bower.Redaction.Privacy;

namespace Bower.Collector;

/// <summary>
/// Wire shape of the management API's signed deployment (<c>ManagedPrivacyProfile</c>) and
/// of the cache file <c>profile.json</c>. Field names are the signed contract.
/// </summary>
internal sealed record ManagedPrivacyProfileDocument(
    string? CollectorId,
    string? VersionId,
    string? ProfileId,
    string? Version,
    string? ContentHash,
    string? Content,
    string? IssuedAt,
    DetachedSignature? Signature);

/// <summary>A managed privacy profile that failed verification. Messages are metadata only.</summary>
public sealed class ManagedPrivacyProfileException(string message) : Exception(message);

/// <summary>A signed, collector-bound, loader-validated managed privacy profile.</summary>
public sealed record VerifiedManagedPrivacyProfile(
    LoadedPrivacyProfile Profile,
    string VersionId,
    string ProfileId,
    string Version,
    string ContentHash);

/// <summary>
/// Verification and the local cache for managed privacy profiles. A document is trusted
/// only when a configured key signed it, it names this collector, the loader accepts its
/// content with the collector's real HMAC key, and the content hash matches. Unverified
/// content is never written to disk.
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
    /// Start-up: the verified cached profile, or null when there is no cache (the built-in
    /// default applies). Any verification failure stops start-up: fail closed.
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
                "Delete the cache file to start with the built-in default privacy profile.");
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
                VersionId: { } versionId,
                ProfileId: { } profileId,
                Version: { } version,
                ContentHash: { } contentHash,
                Content: { } content,
                IssuedAt: { } issuedAt,
                Signature: { Algorithm: not null, KeyId: not null, Value: not null } signature
            })
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is incomplete.");
        }

        if (!DetachedSigner.Verify(
                SignedBytes(documentCollector, versionId, profileId, version, contentHash, content, issuedAt),
                signature,
                trustedPublicKeyPems))
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile signature is not trusted.");
        }

        if (!string.Equals(documentCollector, collectorId, StringComparison.Ordinal))
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile was issued for a different collector.");
        }

        LoadedPrivacyProfile profile;
        try
        {
            profile = PrivacyProfileLoader.Load(content, hmacKey, hmacKeyId);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or ArgumentException)
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile {profileId}@{version} failed validation: {exception.Message}");
        }

        if (!string.Equals(profile.Hash, contentHash, StringComparison.Ordinal))
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

        return new VerifiedManagedPrivacyProfile(profile, versionId, profileId, version, contentHash);
    }

    /// <summary>
    /// Canonical JSON of exactly the signed fields. Must match the management API's
    /// <c>ManagedPrivacyProfileSigner.SignedBytes</c> byte for byte.
    /// </summary>
    public static byte[] SignedBytes(
        string collectorId,
        string versionId,
        string profileId,
        string version,
        string contentHash,
        string content,
        string issuedAt) =>
        CanonicalJson.Bytes(new JsonObject
        {
            ["collectorId"] = collectorId,
            ["versionId"] = versionId,
            ["profileId"] = profileId,
            ["version"] = version,
            ["contentHash"] = contentHash,
            ["content"] = content,
            ["issuedAt"] = issuedAt
        });

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
