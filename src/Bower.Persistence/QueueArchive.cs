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
/// Bower never deletes or rewrites a committed segment (one with a manifest). Place the
/// directory on write-once storage to meet records-authority retention. Writers take the
/// exclusive <see cref="WriterLockFile"/> lock before reading the watermark, so writers in
/// either runtime and process exclude each other. While an archive is configured,
/// retention purges only events the archive verifiably holds for this queue (see
/// <see cref="VerifyCoverageAsync"/>).
/// </remarks>
public sealed class QueueArchive
{
    public const int MaximumEventsPerSegment = 10_000;
    public const string ManifestKind = "BowerArchiveSegment";

    /// <summary>
    /// Lock file every archive writer (C# and Rust) holds exclusively for a whole run: an OS
    /// file lock (<c>flock</c> on Unix, a share-mode lock on Windows). It is never deleted.
    /// </summary>
    public const string WriterLockFile = "archive.lock";

    private const string ManifestSuffix = ".manifest.json";
    private const string SegmentSuffix = ".jsonl.gz";
    private const int MaximumManifestBytes = 65_536;
    private const int MaximumLineBytes = 4 * 1_048_576;
    private const int MaximumTemporaryCleanup = 1_000;

    private readonly string directory;
    private readonly string collectorId;
    private readonly TimeProvider clock;
    private VerifiedPrefix? verifiedPrefix;

    public QueueArchive(string directory, string collectorId, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(collectorId);
        this.directory = Path.GetFullPath(directory);
        this.collectorId = collectorId;
        this.clock = clock ?? TimeProvider.System;
    }

    /// <summary>Test hook: runs while the writer owns the archive, before a segment is published.</summary>
    internal Func<CancellationToken, Task>? BeforePublishAsync { get; set; }

    /// <summary>
    /// Last ledger sequence the manifests claim; 0 when empty. Unverified: retention uses
    /// <see cref="VerifyCoverageAsync"/>.
    /// </summary>
    public long ArchivedThroughSequence()
    {
        List<ArchiveManifest> manifests = ReadManifests();
        return manifests.Count == 0 ? 0 : manifests[^1].LastSequence;
    }

    /// <summary>
    /// Copies every stored event not yet archived into new segments. Safe to rerun after a
    /// crash: a segment left without a manifest is rewritten from the queue. Throws
    /// <see cref="IOException"/> without writing when another writer owns the archive.
    /// </summary>
    public async Task<ArchiveRunResult> ArchiveAsync(
        SqliteEventStore store,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        Directory.CreateDirectory(directory);

        // Own the archive before reading the watermark, so no other writer can publish
        // between the read and this run's segments.
        using FileStream ownership = AcquireWriterLock();
        List<ArchiveManifest> manifests = ReadManifests();
        long lastSequence;
        string lastHash;
        if (manifests.Count > 0)
        {
            lastSequence = manifests[^1].LastSequence;
            lastHash = manifests[^1].LastChainHash;
            // Extend only this queue's chain. Another queue's archive, a diverged restore or
            // an archive ahead of the queue is refused before anything is written.
            // A boundary compacted away (the events after it were purged) is left to the
            // purged-before-archived check below, which writes nothing either.
            string? queueHash = await store.GetLedgerHashAtAsync(lastSequence, cancellationToken);
            bool compacted = queueHash is null
                && (await store.GetLedgerHeadAsync(cancellationToken)).Sequence >= lastSequence;
            if (!compacted && !string.Equals(queueHash, lastHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Archive lineage-mismatch: the queue ledger does not match the archive head at sequence {lastSequence}.");
            }
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

        RemoveAbandonedTemporaryFiles();
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

        return await VerifyFromAsync(
            manifests,
            0,
            manifests[0].PreviousChainHash,
            manifests[0].FirstSequence,
            anchor,
            cancellationToken);
    }

    /// <summary>
    /// Verified, contiguous coverage of <paramref name="store"/>'s retained events. Fails
    /// closed (with a metadata-only reason) unless every segment exists and matches its
    /// manifest digest and chain, the archive starts at or below the oldest stored event, and
    /// the archived chain equals the queue ledger chain (same lineage). Segments verified
    /// earlier are not re-read while their manifests, sizes and write times are unchanged.
    /// </summary>
    public async Task<ArchiveCoverage> VerifyCoverageAsync(
        SqliteEventStore store,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        IReadOnlyList<LedgerEvent> oldest = await store.ReadLedgerEventsAsync(0, 1, cancellationToken);
        List<ArchiveManifest> manifests;
        try
        {
            manifests = ReadManifests();
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        {
            return ArchiveCoverage.Refused("manifest-invalid");
        }

        if (manifests.Count == 0)
        {
            // Nothing stored means nothing to purge; otherwise nothing is covered yet.
            return oldest.Count == 0 ? new ArchiveCoverage(true, 0, 0, null) : ArchiveCoverage.Refused("archive-empty");
        }

        long first = manifests[0].FirstSequence;
        if (oldest.Count > 0 && oldest[0].Sequence < first)
        {
            return ArchiveCoverage.Refused("archive-starts-above-retained", first, manifests[^1].LastSequence);
        }

        try
        {
            ArchiveVerification verification = await VerifyIncrementallyAsync(manifests, cancellationToken);
            if (!verification.Intact)
            {
                return ArchiveCoverage.Refused(verification.BreakReason ?? "archive-broken", first);
            }

            // The ledger chain is the queue's lineage: equal hashes at the highest boundary
            // both record prove every archived event up to it came from this queue. Every
            // sequence between that boundary and the archive head is already purged.
            long through = verification.HeadSequence;
            LedgerHead? boundary = await store.GetLedgerBoundaryAtOrBelowAsync(through, cancellationToken);
            if (boundary is null || boundary.Sequence < first - 1)
            {
                return ArchiveCoverage.Refused("lineage-unverifiable", first, through);
            }

            string? archived = await ArchivedHashAtAsync(manifests, boundary.Sequence, cancellationToken);
            return string.Equals(archived, boundary.Hash, StringComparison.Ordinal)
                ? new ArchiveCoverage(true, first, through, null)
                : ArchiveCoverage.Refused("lineage-mismatch", first, through);
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or IOException)
        {
            verifiedPrefix = null;
            return ArchiveCoverage.Refused("segment-unreadable", first);
        }
    }

    /// <summary>
    /// Re-hashes, bypassing the verification cache, each segment holding one of
    /// <paramref name="sequences"/> (the events about to be purged), and checks its
    /// manifest is the one <see cref="VerifyCoverageAsync"/> last verified. Null when all
    /// match; otherwise a metadata-only reason, and the cache is dropped so the next
    /// coverage check verifies everything again.
    /// </summary>
    public async Task<string?> VerifySegmentsForPurgeAsync(
        IReadOnlyCollection<long> sequences,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sequences);
        string? reason = verifiedPrefix is { } cached
            ? await RehashAsync(cached, sequences, cancellationToken)
            : "archive-unverified";
        if (reason is not null)
        {
            verifiedPrefix = null;
        }

        return reason;
    }

    private async Task<string?> RehashAsync(
        VerifiedPrefix cached,
        IReadOnlyCollection<long> sequences,
        CancellationToken cancellationToken)
    {
        SortedSet<int> needed = [];
        foreach (long sequence in sequences)
        {
            int index = FindStamp(cached.Stamps, sequence);
            if (index < 0)
            {
                return "segment-uncovered";
            }

            needed.Add(index);
        }

        try
        {
            Dictionary<long, ArchiveManifest> current = ReadManifests().ToDictionary(item => item.FirstSequence);
            foreach (int index in needed)
            {
                ArchiveManifest manifest = cached.Stamps[index].Manifest;
                if (!current.TryGetValue(manifest.FirstSequence, out ArchiveManifest? onDisk) || onDisk != manifest)
                {
                    return "archive-changed";
                }

                string segmentPath = Path.Combine(directory, manifest.SegmentFile);
                if (!File.Exists(segmentPath))
                {
                    return "segment-missing";
                }

                if (!string.Equals(await DigestAsync(segmentPath, cancellationToken), manifest.SegmentSha256, StringComparison.Ordinal))
                {
                    return "segment-digest-mismatch";
                }
            }
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        {
            return "manifest-invalid";
        }
        catch (IOException)
        {
            return "segment-unreadable";
        }

        return null;
    }

    /// <summary>Index of the stamp whose segment holds <paramref name="sequence"/>; -1 when none.</summary>
    private static int FindStamp(SegmentStamp[] stamps, long sequence)
    {
        int low = 0;
        int high = stamps.Length - 1;
        while (low <= high)
        {
            int middle = low + ((high - low) / 2);
            ArchiveManifest manifest = stamps[middle].Manifest;
            if (sequence < manifest.FirstSequence)
            {
                high = middle - 1;
            }
            else if (sequence > manifest.LastSequence)
            {
                low = middle + 1;
            }
            else
            {
                return middle;
            }
        }

        return -1;
    }

    private async Task<ArchiveVerification> VerifyIncrementallyAsync(
        List<ArchiveManifest> manifests,
        CancellationToken cancellationToken)
    {
        // Stamp before reading, so a change made during verification invalidates the cache.
        SegmentStamp[] stamps = [.. manifests.Select(manifest =>
        {
            FileInfo segment = new(Path.Combine(directory, manifest.SegmentFile));
            return segment.Exists
                ? new SegmentStamp(manifest, segment.Length, segment.LastWriteTimeUtc)
                : new SegmentStamp(manifest, -1, default);
        })];
        int start = 0;
        string previous = manifests[0].PreviousChainHash;
        long expected = manifests[0].FirstSequence;
        if (verifiedPrefix is { } cached
            && cached.Stamps.Length <= stamps.Length
            && cached.Stamps.AsSpan().SequenceEqual(stamps.AsSpan(0, cached.Stamps.Length)))
        {
            start = cached.Stamps.Length;
            previous = cached.HeadHash;
            expected = cached.HeadSequence + 1;
        }

        verifiedPrefix = null;
        ArchiveVerification result = await VerifyFromAsync(manifests, start, previous, expected, null, cancellationToken);
        if (result.Intact)
        {
            verifiedPrefix = new VerifiedPrefix(stamps, result.HeadSequence, result.HeadHash!);
        }

        return result;
    }

    private async Task<string?> ArchivedHashAtAsync(
        List<ArchiveManifest> manifests,
        long sequence,
        CancellationToken cancellationToken)
    {
        if (sequence == manifests[0].FirstSequence - 1)
        {
            return manifests[0].PreviousChainHash;
        }

        ArchiveManifest? manifest = manifests.Find(item => item.FirstSequence <= sequence && sequence <= item.LastSequence);
        if (manifest is null || sequence == manifest.LastSequence)
        {
            return manifest?.LastChainHash;
        }

        await foreach (ArchivedEvent item in ReadSegmentAsync(Path.Combine(directory, manifest.SegmentFile), cancellationToken))
        {
            if (item.Sequence == sequence)
            {
                return item.ChainHash;
            }
        }

        return null;
    }

    private async Task<ArchiveVerification> VerifyFromAsync(
        List<ArchiveManifest> manifests,
        int start,
        string previous,
        long expected,
        LedgerHead? anchor,
        CancellationToken cancellationToken)
    {
        long verified = 0;
        bool anchorVerified = false;
        foreach (ArchiveManifest manifest in manifests.Skip(start))
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
        string manifestPath = Path.Combine(directory, name + ManifestSuffix);
        string temporary = TemporaryPath(segmentPath);
        string manifestTemporary = TemporaryPath(manifestPath);
        try
        {
            return await PublishSegmentAsync(
                rows,
                previousHash,
                segmentFile,
                segmentPath,
                manifestPath,
                temporary,
                manifestTemporary,
                cancellationToken);
        }
        finally
        {
            File.Delete(temporary);
            File.Delete(manifestTemporary);
        }
    }

    private async Task<ArchiveManifest> PublishSegmentAsync(
        LedgerEvent[] rows,
        string previousHash,
        string segmentFile,
        string segmentPath,
        string manifestPath,
        string temporary,
        string manifestTemporary,
        CancellationToken cancellationToken)
    {
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

        if (BeforePublishAsync is { } beforePublish)
        {
            await beforePublish(cancellationToken);
        }

        // Only the lock owner gets here, so a segment without a manifest is an uncommitted
        // orphan of a crashed run. A committed segment is never replaced: the move fails.
        if (!Path.Exists(manifestPath) && File.Exists(segmentPath))
        {
            File.Delete(segmentPath);
        }

        File.Move(temporary, segmentPath, overwrite: false);
        RestrictPermissions(segmentPath);
        // Make the published names durable before retention can rely on them.
        DirectorySync.Flush(directory);

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
        await using (FileStream file = new(manifestTemporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(file, manifest, ArchiveJsonContext.Default.ArchiveManifest, cancellationToken);
            file.Flush(flushToDisk: true);
        }

        // Never replace a completed manifest: a collision means two writers share the archive.
        File.Move(manifestTemporary, manifestPath, overwrite: false);
        RestrictPermissions(manifestPath);
        DirectorySync.Flush(directory);
        return manifest;
    }

    private FileStream AcquireWriterLock()
    {
        string path = Path.Combine(directory, WriterLockFile);
        FileStream ownership;
        try
        {
            ownership = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException exception)
        {
            throw new IOException("Another writer holds the archive writer lock.", exception);
        }

        try
        {
            ProveExclusiveOwnership(path);
            return ownership;
        }
        catch
        {
            ownership.Dispose();
            throw;
        }
    }

    /// <summary>
    /// .NET skips the lock silently where the file system does not support it, or when
    /// <c>DOTNET_SYSTEM_IO_DISABLEFILELOCKING</c> is set. While the lock is held a second
    /// exclusive open must fail; if it succeeds nothing excludes other writers.
    /// </summary>
    internal static void ProveExclusiveOwnership(string path)
    {
        FileStream second;
        try
        {
            second = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            return;
        }

        second.Dispose();
        throw new IOException("The archive writer lock is not enforced on this file system; refusing to write.");
    }

    /// <summary>Removes temporary files of crashed runs. Call only while owning the archive.</summary>
    private void RemoveAbandonedTemporaryFiles()
    {
        foreach (string path in Directory.EnumerateFiles(directory, "segment-*.tmp").Take(MaximumTemporaryCleanup).ToArray())
        {
            File.Delete(path);
        }
    }

    private static string TemporaryPath(string path) =>
        $"{path}.{Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)}.tmp";

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

/// <summary>
/// Archive coverage retention may rely on: events <paramref name="FirstSequence"/> to
/// <paramref name="ThroughSequence"/> when <paramref name="Verified"/>; otherwise a
/// metadata-only <paramref name="Reason"/> and nothing may be purged.
/// </summary>
public sealed record ArchiveCoverage(bool Verified, long FirstSequence, long ThroughSequence, string? Reason)
{
    public static ArchiveCoverage Refused(string reason, long firstSequence = 0, long throughSequence = 0) =>
        new(false, firstSequence, throughSequence, reason);
}

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

internal readonly record struct SegmentStamp(ArchiveManifest Manifest, long Length, DateTime WrittenUtc);

internal sealed record VerifiedPrefix(SegmentStamp[] Stamps, long HeadSequence, string HeadHash);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ArchivedEvent))]
[JsonSerializable(typeof(ArchiveManifest))]
internal sealed partial class ArchiveJsonContext : JsonSerializerContext;
