using System.Globalization;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;

namespace Bower.Persistence;

/// <summary>
/// Long-term, self-verifying copy of every accepted event. Segments are gzip JSON Lines of
/// ledger entries with their payloads; each has a manifest with the file digest and the
/// ledger chain hash at both ends. The archive continues the queue ledger chain, so it can
/// be verified without the queue and checked against a head witnessed by management.
/// </summary>
/// <remarks>
/// Bower never deletes or rewrites a completed segment. Place the directory on write-once
/// storage to meet records-authority retention. While an archive is configured, retention
/// purges only events the archive already holds (see <see cref="ArchivedThroughSequence"/>).
/// </remarks>
public sealed class QueueArchive
{
    public const int MaximumEventsPerSegment = 10_000;
    public const string ManifestKind = "BowerArchiveSegment";

    private const string ManifestSuffix = ".manifest.json";
    private const string SegmentSuffix = ".jsonl.gz";
    private const int MaximumManifestBytes = 65_536;
    private const int MaximumLineBytes = 4 * 1_048_576;

    private readonly string directory;
    private readonly string collectorId;
    private readonly TimeProvider clock;

    public QueueArchive(string directory, string collectorId, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(collectorId);
        this.directory = Path.GetFullPath(directory);
        this.collectorId = collectorId;
        this.clock = clock ?? TimeProvider.System;
    }

    /// <summary>Last ledger sequence the archive holds; 0 when empty.</summary>
    public long ArchivedThroughSequence()
    {
        List<ArchiveManifest> manifests = ReadManifests();
        return manifests.Count == 0 ? 0 : manifests[^1].LastSequence;
    }

    /// <summary>
    /// Copies every stored event not yet archived into new segments. Safe to rerun after a
    /// crash: a segment left without a manifest is rewritten from the queue.
    /// </summary>
    public async Task<ArchiveRunResult> ArchiveAsync(
        SqliteEventStore store,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        Directory.CreateDirectory(directory);

        List<ArchiveManifest> manifests = ReadManifests();
        long lastSequence;
        string lastHash;
        if (manifests.Count > 0)
        {
            lastSequence = manifests[^1].LastSequence;
            lastHash = manifests[^1].LastChainHash;
        }
        else
        {
            // A new archive starts at the oldest event still stored; its first manifest
            // records the ledger hash before it, so the chain continues from the queue.
            IReadOnlyList<LedgerEvent> first = await store.ReadLedgerEventsAsync(0, 1, cancellationToken);
            if (first.Count == 0)
            {
                return new ArchiveRunResult(0, 0, 0, null);
            }

            lastSequence = first[0].Sequence - 1;
            lastHash = await store.GetLedgerHashAtAsync(lastSequence, cancellationToken)
                ?? throw new InvalidDataException(
                    $"Ledger no longer records the hash at sequence {lastSequence}; cannot start the archive.");
        }

        int segments = 0;
        long events = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            IReadOnlyList<LedgerEvent> rows = await store.ReadLedgerEventsAsync(
                lastSequence,
                MaximumEventsPerSegment,
                cancellationToken);
            if (rows.Count == 0)
            {
                break;
            }

            if (rows[0].Sequence != lastSequence + 1)
            {
                throw new InvalidDataException(
                    $"Events after sequence {lastSequence} were purged before they were archived.");
            }

            int contiguous = 1;
            while (contiguous < rows.Count && rows[contiguous].Sequence == rows[contiguous - 1].Sequence + 1)
            {
                contiguous++;
            }

            ArchiveManifest manifest = await WriteSegmentAsync(
                rows.Take(contiguous).ToArray(),
                lastHash,
                cancellationToken);
            lastSequence = manifest.LastSequence;
            lastHash = manifest.LastChainHash;
            segments++;
            events += contiguous;
            if (contiguous < rows.Count)
            {
                // The next row follows a gap: stop and report it on the next run.
                break;
            }
        }

        return new ArchiveRunResult(segments, events, lastSequence, lastHash);
    }

    /// <summary>
    /// Recomputes every ledger link across all segments and checks each file digest. With
    /// <paramref name="anchor"/>, also proves the archived chain passes through that head.
    /// </summary>
    public async Task<ArchiveVerification> VerifyAsync(
        LedgerHead? anchor = null,
        CancellationToken cancellationToken = default)
    {
        List<ArchiveManifest> manifests;
        try
        {
            manifests = ReadManifests();
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        {
            return ArchiveVerification.Broken(0, 0, null, "manifest-invalid");
        }

        if (manifests.Count == 0)
        {
            return ArchiveVerification.Broken(0, 0, null, "archive-empty");
        }

        long verified = 0;
        bool anchorVerified = false;
        string previous = manifests[0].PreviousChainHash;
        long expected = manifests[0].FirstSequence;
        foreach (ArchiveManifest manifest in manifests)
        {
            string segmentPath = Path.Combine(directory, manifest.SegmentFile);
            if (!File.Exists(segmentPath))
            {
                return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "segment-missing");
            }

            if (!string.Equals(await DigestAsync(segmentPath, cancellationToken), manifest.SegmentSha256, StringComparison.Ordinal))
            {
                return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "segment-digest-mismatch");
            }

            if (!string.Equals(previous, manifest.PreviousChainHash, StringComparison.Ordinal))
            {
                return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "segment-not-contiguous");
            }

            long count = 0;
            await foreach (ArchivedEvent item in ReadSegmentAsync(segmentPath, cancellationToken))
            {
                count++;
                if (item.Sequence != expected)
                {
                    return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "sequence-gap");
                }

                string computed = QueueLedger.Chain(
                    previous,
                    item.Sequence,
                    item.EventId,
                    QueueLedger.PayloadHash(item.Payload),
                    item.ReceivedAt);
                if (!string.Equals(computed, item.ChainHash, StringComparison.Ordinal))
                {
                    return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "chain-broken");
                }

                if (anchor is not null && item.Sequence == anchor.Sequence)
                {
                    if (!string.Equals(computed, anchor.Hash, StringComparison.Ordinal))
                    {
                        return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "anchor-mismatch");
                    }

                    anchorVerified = true;
                }

                previous = computed;
                expected++;
                verified++;
            }

            if (count != manifest.EventCount
                || expected - 1 != manifest.LastSequence
                || !string.Equals(previous, manifest.LastChainHash, StringComparison.Ordinal))
            {
                return ArchiveVerification.Broken(verified, manifests.Count, manifest.SegmentFile, "manifest-mismatch");
            }
        }

        if (anchor is not null && !anchorVerified)
        {
            return ArchiveVerification.Broken(verified, manifests.Count, null, "anchor-missing");
        }

        return new ArchiveVerification(
            true,
            manifests.Count,
            verified,
            manifests[0].FirstSequence,
            expected - 1,
            previous,
            anchorVerified,
            null,
            null);
    }

    /// <summary>Streams archived events in ledger order. Verify first.</summary>
    public async IAsyncEnumerable<ArchivedEvent> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (ArchiveManifest manifest in ReadManifests())
        {
            await foreach (ArchivedEvent item in ReadSegmentAsync(
                               Path.Combine(directory, manifest.SegmentFile),
                               cancellationToken))
            {
                yield return item;
            }
        }
    }

    private async Task<ArchiveManifest> WriteSegmentAsync(
        LedgerEvent[] rows,
        string previousHash,
        CancellationToken cancellationToken)
    {
        string name = $"segment-{rows[0].Sequence.ToString("D12", CultureInfo.InvariantCulture)}";
        string segmentFile = name + SegmentSuffix;
        string segmentPath = Path.Combine(directory, segmentFile);
        string temporary = segmentPath + ".tmp";

        await using (FileStream file = new(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await using (GZipStream gzip = new(file, CompressionLevel.Optimal, leaveOpen: true))
            await using (StreamWriter writer = new(gzip, new UTF8Encoding(false)))
            {
                foreach (LedgerEvent row in rows)
                {
                    await writer.WriteAsync(JsonSerializer.Serialize(
                        new ArchivedEvent(row.Sequence, row.EventId, row.ReceivedAt, row.ChainHash, row.Payload),
                        ArchiveJsonContext.Default.ArchivedEvent).AsMemory(), cancellationToken);
                    await writer.WriteAsync("\n".AsMemory(), cancellationToken);
                }
            }

            file.Flush(flushToDisk: true);
        }

        File.Move(temporary, segmentPath, overwrite: true);
        RestrictPermissions(segmentPath);

        ArchiveManifest manifest = new(
            "bower.security/v1",
            ManifestKind,
            collectorId,
            segmentFile,
            await DigestAsync(segmentPath, cancellationToken),
            rows[0].Sequence,
            rows[^1].Sequence,
            rows.Length,
            previousHash,
            rows[^1].ChainHash,
            clock.GetUtcNow());
        string manifestPath = Path.Combine(directory, name + ManifestSuffix);
        string manifestTemporary = manifestPath + ".tmp";
        await using (FileStream file = new(manifestTemporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(file, manifest, ArchiveJsonContext.Default.ArchiveManifest, cancellationToken);
            file.Flush(flushToDisk: true);
        }

        // Never replace a completed manifest: a collision means two writers share the archive.
        File.Move(manifestTemporary, manifestPath, overwrite: false);
        RestrictPermissions(manifestPath);
        return manifest;
    }

    private List<ArchiveManifest> ReadManifests()
    {
        if (!Directory.Exists(directory))
        {
            return [];
        }

        List<ArchiveManifest> manifests = [];
        foreach (string path in Directory.EnumerateFiles(directory, "segment-*" + ManifestSuffix))
        {
            if (new FileInfo(path).Length > MaximumManifestBytes)
            {
                throw new InvalidDataException($"Archive manifest too large: {Path.GetFileName(path)}");
            }

            ArchiveManifest manifest = JsonSerializer.Deserialize(
                    File.ReadAllText(path, Encoding.UTF8),
                    ArchiveJsonContext.Default.ArchiveManifest)
                ?? throw new InvalidDataException($"Archive manifest empty: {Path.GetFileName(path)}");
            if (!string.Equals(manifest.Kind, ManifestKind, StringComparison.Ordinal)
                || string.IsNullOrEmpty(manifest.SegmentFile)
                || !string.Equals(Path.GetFileName(manifest.SegmentFile), manifest.SegmentFile, StringComparison.Ordinal)
                || manifest.FirstSequence < 1
                || manifest.LastSequence < manifest.FirstSequence
                || manifest.EventCount != manifest.LastSequence - manifest.FirstSequence + 1)
            {
                throw new InvalidDataException($"Archive manifest invalid: {Path.GetFileName(path)}");
            }

            manifests.Add(manifest);
        }

        manifests.Sort((left, right) => left.FirstSequence.CompareTo(right.FirstSequence));
        for (int index = 1; index < manifests.Count; index++)
        {
            if (manifests[index].FirstSequence != manifests[index - 1].LastSequence + 1)
            {
                throw new InvalidDataException(
                    $"Archive is missing sequences before {manifests[index].FirstSequence}.");
            }
        }

        return manifests;
    }

    private static async IAsyncEnumerable<ArchivedEvent> ReadSegmentAsync(
        string path,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using GZipStream gzip = new(file, CompressionMode.Decompress);
        using StreamReader reader = new(gzip, Encoding.UTF8);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (line.Length > MaximumLineBytes)
            {
                throw new InvalidDataException("Archived line exceeds maximum size.");
            }

            yield return JsonSerializer.Deserialize(line, ArchiveJsonContext.Default.ArchivedEvent)
                ?? throw new InvalidDataException("Archived line is empty.");
        }
    }

    private static async Task<string> DigestAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return $"sha256:{Convert.ToHexStringLower(await SHA256.HashDataAsync(file, cancellationToken))}";
    }

    private static void RestrictPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

/// <param name="Payload">Redacted envelope JSON exactly as queued, kept as a string so its digest is reproducible.</param>
public sealed record ArchivedEvent(
    long Sequence,
    string EventId,
    string ReceivedAt,
    string ChainHash,
    string Payload);

public sealed record ArchiveManifest(
    string ApiVersion,
    string Kind,
    string CollectorId,
    string SegmentFile,
    string SegmentSha256,
    long FirstSequence,
    long LastSequence,
    long EventCount,
    string PreviousChainHash,
    string LastChainHash,
    DateTimeOffset CreatedAt);

public sealed record ArchiveRunResult(int Segments, long Events, long HeadSequence, string? HeadHash);

public sealed record ArchiveVerification(
    bool Intact,
    int Segments,
    long VerifiedEvents,
    long FirstSequence,
    long HeadSequence,
    string? HeadHash,
    bool AnchorVerified,
    string? BreakSegment,
    string? BreakReason)
{
    internal static ArchiveVerification Broken(long verified, int segments, string? segment, string reason) =>
        new(false, segments, verified, 0, 0, null, false, segment, reason);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ArchivedEvent))]
[JsonSerializable(typeof(ArchiveManifest))]
internal sealed partial class ArchiveJsonContext : JsonSerializerContext;
