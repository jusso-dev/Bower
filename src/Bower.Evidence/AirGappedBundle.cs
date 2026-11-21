using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Integrity;

namespace Bower.Evidence;

/// <summary>
/// Signed manifest of an air-gapped export bundle (<c>.bowerbundle</c>). Every bundle chains
/// to its predecessor via <see cref="BundleSequence"/> and <see cref="PreviousBundleHash"/>,
/// and binds the already-redacted NDJSON payload via <see cref="EventsSha256"/>.
/// </summary>
public sealed record AirGappedBundleManifest(
    string Kind,
    string BundleId,
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string PolicyHash,
    string PrivacyProfileHash,
    long BundleSequence,
    string PreviousBundleHash,
    long FromLedgerSequence,
    long ToLedgerSequence,
    string LedgerHeadHash,
    long EventCount,
    long QueueDepth,
    long DeadLettered,
    string EventsSha256,
    bool Encrypted,
    string CreatedAt)
{
    public const string CurrentKind = "bower.airgapped.bundle.v1";
    public const string GenesisBundleHash = "genesis";
}

/// <summary>
/// Metadata-only offline site status report extracted from an air-gapped bundle and posted
/// to <c>POST /api/fleet/offline-import</c>. Contains zero event payloads, preserving the
/// management-plane metadata-only invariant (ISM-1985).
/// </summary>
public sealed record OfflineSiteReportDocument(
    string Kind,
    string BundleId,
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string PolicyHash,
    string PrivacyProfileHash,
    long BundleSequence,
    string PreviousBundleHash,
    string BundleHash,
    long LedgerSequence,
    string LedgerHeadHash,
    long EventCount,
    long QueueDepth,
    long DeadLettered,
    string ExportedAt)
{
    public const string CurrentKind = "bower.offline.report.v1";
}

/// <summary>Signed metadata-only offline site status report.</summary>
public sealed record SignedOfflineSiteReport(
    OfflineSiteReportDocument Report,
    DetachedSignature Signature);

/// <summary>Result of creating an air-gapped export bundle.</summary>
public sealed record AirGappedExportResult(
    string BundlePath,
    string BundleId,
    long BundleSequence,
    string BundleHash,
    long FromLedgerSequence,
    long ToLedgerSequence,
    long EventCount,
    bool Encrypted);

/// <summary>Result of verifying an air-gapped export bundle.</summary>
public sealed record AirGappedBundleVerification(
    bool Valid,
    string? Error,
    AirGappedBundleManifest? Manifest,
    string? BundleHash,
    SignedOfflineSiteReport? OfflineReport);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, WriteIndented = true)]
[JsonSerializable(typeof(AirGappedBundleManifest))]
[JsonSerializable(typeof(DetachedSignature))]
[JsonSerializable(typeof(OfflineSiteReportDocument))]
[JsonSerializable(typeof(SignedOfflineSiteReport))]
public sealed partial class AirGappedBundleJsonContext : JsonSerializerContext;

/// <summary>
/// Creates, verifies and reads signed, hash-chained air-gapped export bundles
/// (<c>.bowerbundle</c>) with optional AES-256-GCM payload encryption.
/// </summary>
public static class AirGappedBundle
{
    private const string ManifestEntry = "manifest.json";
    private const string ManifestSigEntry = "manifest.sig";
    private const string PlainEventsEntry = "events.ndjson";
    private const string EncryptedEventsEntry = "events.ndjson.enc";
    private const string StatusReportEntry = "status-report.json";
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int AesKeyBytes = 32;

    public static AirGappedExportResult Create(
        string outputPath,
        AirGappedBundleManifest manifestTemplate,
        IEnumerable<string> redactedEventJsonLines,
        string signingPrivateKeyPem,
        byte[]? encryptionKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(manifestTemplate);
        ArgumentNullException.ThrowIfNull(redactedEventJsonLines);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingPrivateKeyPem);
        if (encryptionKey is not null && encryptionKey.Length != AesKeyBytes)
        {
            throw new ArgumentException($"Encryption key must be exactly {AesKeyBytes} bytes (AES-256-GCM).", nameof(encryptionKey));
        }

        StringBuilder ndjson = new();
        long count = 0;
        foreach (string line in redactedEventJsonLines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            // Normalize to single-line NDJSON so line counts stay exact.
            ndjson.Append(line.Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", string.Empty, StringComparison.Ordinal));
            ndjson.Append('\n');
            count++;
        }

        byte[] plainBytes = Encoding.UTF8.GetBytes(ndjson.ToString());
        string eventsSha256 = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(plainBytes));
        bool encrypted = encryptionKey is not null;

        AirGappedBundleManifest manifest = manifestTemplate with
        {
            Kind = AirGappedBundleManifest.CurrentKind,
            EventCount = count,
            EventsSha256 = eventsSha256,
            Encrypted = encrypted
        };

        byte[] manifestCanonical = CanonicalJson.Bytes(
            JsonSerializer.SerializeToNode(manifest, AirGappedBundleJsonContext.Default.AirGappedBundleManifest)!);
        string bundleHash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(manifestCanonical));
        DetachedSignature manifestSignature = DetachedSigner.Sign(manifestCanonical, signingPrivateKeyPem);

        OfflineSiteReportDocument reportDoc = new(
            OfflineSiteReportDocument.CurrentKind,
            manifest.BundleId,
            manifest.CollectorId,
            manifest.MachineName,
            manifest.Environment,
            manifest.Version,
            manifest.PolicyHash,
            manifest.PrivacyProfileHash,
            manifest.BundleSequence,
            manifest.PreviousBundleHash,
            bundleHash,
            manifest.ToLedgerSequence,
            manifest.LedgerHeadHash,
            manifest.EventCount,
            manifest.QueueDepth,
            manifest.DeadLettered,
            manifest.CreatedAt);
        byte[] reportCanonical = CanonicalJson.Bytes(
            JsonSerializer.SerializeToNode(reportDoc, AirGappedBundleJsonContext.Default.OfflineSiteReportDocument)!);
        DetachedSignature reportSignature = DetachedSigner.Sign(reportCanonical, signingPrivateKeyPem);
        SignedOfflineSiteReport signedReport = new(reportDoc, reportSignature);

        byte[] payloadBytes = encrypted
            ? EncryptPayload(plainBytes, encryptionKey!, manifestCanonical)
            : plainBytes;

        string fullOutput = Path.GetFullPath(outputPath);
        string? directory = Path.GetDirectoryName(fullOutput);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string tempPath = fullOutput + $".{Guid.NewGuid():N}.tmp";
        try
        {
            using (FileStream fs = new(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (ZipArchive zip = new(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                WriteEntry(zip, ManifestEntry, JsonSerializer.SerializeToUtf8Bytes(manifest, AirGappedBundleJsonContext.Default.AirGappedBundleManifest));
                WriteEntry(zip, ManifestSigEntry, JsonSerializer.SerializeToUtf8Bytes(manifestSignature, AirGappedBundleJsonContext.Default.DetachedSignature));
                WriteEntry(zip, encrypted ? EncryptedEventsEntry : PlainEventsEntry, payloadBytes);
                WriteEntry(zip, StatusReportEntry, JsonSerializer.SerializeToUtf8Bytes(signedReport, AirGappedBundleJsonContext.Default.SignedOfflineSiteReport));
            }

            File.Move(tempPath, fullOutput, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }

        return new AirGappedExportResult(
            fullOutput,
            manifest.BundleId,
            manifest.BundleSequence,
            bundleHash,
            manifest.FromLedgerSequence,
            manifest.ToLedgerSequence,
            manifest.EventCount,
            encrypted);
    }

    public static AirGappedBundleVerification Verify(
        string bundlePath,
        IEnumerable<string> trustedPublicKeyPems,
        long? expectedSequence = null,
        string? expectedPreviousBundleHash = null,
        byte[]? decryptionKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundlePath);
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        string[] keys = trustedPublicKeyPems.ToArray();
        if (keys.Length == 0)
        {
            return Invalid("At least one trusted public key is required.");
        }

        if (!File.Exists(bundlePath))
        {
            return Invalid("Bundle file does not exist.");
        }

        try
        {
            using ZipArchive zip = ZipFile.OpenRead(bundlePath);
            byte[]? manifestBytes = ReadEntry(zip, ManifestEntry);
            byte[]? sigBytes = ReadEntry(zip, ManifestSigEntry);
            byte[]? reportBytes = ReadEntry(zip, StatusReportEntry);
            if (manifestBytes is null || sigBytes is null || reportBytes is null)
            {
                return Invalid("Bundle is missing manifest.json, manifest.sig or status-report.json.");
            }

            AirGappedBundleManifest? manifest = JsonSerializer.Deserialize(
                manifestBytes, AirGappedBundleJsonContext.Default.AirGappedBundleManifest);
            DetachedSignature? signature = JsonSerializer.Deserialize(
                sigBytes, AirGappedBundleJsonContext.Default.DetachedSignature);
            SignedOfflineSiteReport? signedReport = JsonSerializer.Deserialize(
                reportBytes, AirGappedBundleJsonContext.Default.SignedOfflineSiteReport);
            if (manifest is null || signature is null || signedReport is null)
            {
                return Invalid("Bundle metadata could not be parsed.");
            }

            if (!string.Equals(manifest.Kind, AirGappedBundleManifest.CurrentKind, StringComparison.Ordinal))
            {
                return Invalid("Unsupported bundle manifest kind.");
            }

            byte[] manifestCanonical = CanonicalJson.Bytes(
                JsonSerializer.SerializeToNode(manifest, AirGappedBundleJsonContext.Default.AirGappedBundleManifest)!);
            if (!DetachedSigner.Verify(manifestCanonical, signature, keys))
            {
                return Invalid("Bundle manifest signature verification failed.");
            }

            string bundleHash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(manifestCanonical));
            if (!VerifyOfflineSiteReport(signedReport, keys)
                || !string.Equals(signedReport.Report.BundleHash, bundleHash, StringComparison.Ordinal)
                || !string.Equals(signedReport.Report.CollectorId, manifest.CollectorId, StringComparison.Ordinal)
                || signedReport.Report.BundleSequence != manifest.BundleSequence)
            {
                return Invalid("Bundle offline status report signature or binding verification failed.");
            }

            if (expectedSequence is { } seq && manifest.BundleSequence != seq)
            {
                return Invalid($"Expected bundle sequence {seq}, found {manifest.BundleSequence}.");
            }

            if (expectedPreviousBundleHash is { } prev
                && !string.Equals(manifest.PreviousBundleHash, prev, StringComparison.Ordinal))
            {
                return Invalid("Bundle previousBundleHash does not match the expected chain hash.");
            }

            byte[]? rawPayload = ReadEntry(zip, manifest.Encrypted ? EncryptedEventsEntry : PlainEventsEntry);
            if (rawPayload is null)
            {
                return Invalid("Bundle event payload entry is missing.");
            }

            byte[] plainBytes;
            if (manifest.Encrypted)
            {
                if (decryptionKey is null || decryptionKey.Length != AesKeyBytes)
                {
                    return Invalid("Bundle is encrypted; provide a 32-byte --decrypt-key-file.");
                }

                plainBytes = DecryptPayload(rawPayload, decryptionKey, manifestCanonical);
            }
            else
            {
                plainBytes = rawPayload;
            }

            string actualEventsHash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(plainBytes));
            if (!string.Equals(actualEventsHash, manifest.EventsSha256, StringComparison.Ordinal))
            {
                return Invalid("Event payload digest does not match signed manifest.");
            }

            long actualLines = CountNonEmptyLines(plainBytes);
            if (actualLines != manifest.EventCount)
            {
                return Invalid($"Event count mismatch: manifest declares {manifest.EventCount}, payload has {actualLines}.");
            }

            return new AirGappedBundleVerification(true, null, manifest, bundleHash, signedReport);
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or CryptographicException or IOException)
        {
            return Invalid($"Bundle verification failed ({exception.GetType().Name}).");
        }
    }

    public static IReadOnlyList<string> ReadVerifiedEvents(
        string bundlePath,
        IEnumerable<string> trustedPublicKeyPems,
        byte[]? decryptionKey = null)
    {
        AirGappedBundleVerification verification = Verify(bundlePath, trustedPublicKeyPems, decryptionKey: decryptionKey);
        if (!verification.Valid || verification.Manifest is null)
        {
            throw new InvalidDataException(verification.Error ?? "Bundle verification failed.");
        }

        using ZipArchive zip = ZipFile.OpenRead(bundlePath);
        byte[] raw = ReadEntry(zip, verification.Manifest.Encrypted ? EncryptedEventsEntry : PlainEventsEntry)
            ?? throw new InvalidDataException("Bundle event payload entry is missing.");
        byte[] plain = verification.Manifest.Encrypted
            ? DecryptPayload(
                raw,
                decryptionKey!,
                CanonicalJson.Bytes(JsonSerializer.SerializeToNode(verification.Manifest, AirGappedBundleJsonContext.Default.AirGappedBundleManifest)!))
            : raw;

        List<string> lines = [];
        using MemoryStream stream = new(plain);
        using StreamReader reader = new(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                lines.Add(line);
            }
        }

        return lines;
    }

    public static bool VerifyOfflineSiteReport(
        SignedOfflineSiteReport signedReport,
        IEnumerable<string> trustedPublicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(signedReport);
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        if (signedReport.Report is null
            || signedReport.Signature is null
            || !string.Equals(signedReport.Report.Kind, OfflineSiteReportDocument.CurrentKind, StringComparison.Ordinal))
        {
            return false;
        }

        byte[] canonical = CanonicalJson.Bytes(
            JsonSerializer.SerializeToNode(signedReport.Report, AirGappedBundleJsonContext.Default.OfflineSiteReportDocument)!);
        return DetachedSigner.Verify(canonical, signedReport.Signature, trustedPublicKeyPems);
    }

    public static byte[] ReadEncryptionKeyFile(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length == AesKeyBytes)
        {
            return bytes;
        }

        string text = Encoding.UTF8.GetString(bytes).Trim();
        if (text.Length == 64 && text.All(char.IsAsciiHexDigit))
        {
            return Convert.FromHexString(text);
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(text);
            if (decoded.Length == AesKeyBytes)
            {
                return decoded;
            }
        }
        catch (FormatException)
        {
        }

        throw new ArgumentException("Encryption key file must contain 32 raw bytes, 64 hex chars, or 32-byte base64.");
    }

    private static byte[] EncryptPayload(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagBytes];
        using AesGcm aes = new(key, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        byte[] combined = new byte[NonceBytes + TagBytes + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, NonceBytes);
        Buffer.BlockCopy(tag, 0, combined, NonceBytes, TagBytes);
        Buffer.BlockCopy(ciphertext, 0, combined, NonceBytes + TagBytes, ciphertext.Length);
        return combined;
    }

    private static byte[] DecryptPayload(byte[] combined, byte[] key, byte[] associatedData)
    {
        if (combined.Length < NonceBytes + TagBytes)
        {
            throw new CryptographicException("Encrypted payload is truncated.");
        }

        ReadOnlySpan<byte> span = combined;
        ReadOnlySpan<byte> nonce = span[..NonceBytes];
        ReadOnlySpan<byte> tag = span[NonceBytes..(NonceBytes + TagBytes)];
        ReadOnlySpan<byte> ciphertext = span[(NonceBytes + TagBytes)..];
        byte[] plaintext = new byte[ciphertext.Length];
        using AesGcm aes = new(key, TagBytes);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    private static void WriteEntry(ZipArchive zip, string name, byte[] bytes)
    {
        ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using Stream stream = entry.Open();
        stream.Write(bytes);
    }

    private static byte[]? ReadEntry(ZipArchive zip, string name)
    {
        ZipArchiveEntry? entry = zip.GetEntry(name);
        if (entry is null)
        {
            return null;
        }

        using Stream stream = entry.Open();
        using MemoryStream memory = new();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static long CountNonEmptyLines(byte[] utf8Bytes)
    {
        long count = 0;
        using MemoryStream stream = new(utf8Bytes);
        using StreamReader reader = new(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                count++;
            }
        }

        return count;
    }

    private static AirGappedBundleVerification Invalid(string error) =>
        new(false, error, null, null, null);
}
