using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.UnitTests;

public sealed class QueueArchiveTests
{
    [Fact]
    public async Task Archive_ContinuesLedgerChainAcrossRunsAndVerifiesAgainstQueueHead()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);

        await EnqueueAsync(store, 1, 3, clock, cancellationToken);
        ArchiveRunResult first = await archive.ArchiveAsync(store, cancellationToken);
        ArchiveRunResult idle = await archive.ArchiveAsync(store, cancellationToken);
        await EnqueueAsync(store, 4, 5, clock, cancellationToken);
        ArchiveRunResult second = await archive.ArchiveAsync(store, cancellationToken);
        LedgerHead head = await store.GetLedgerHeadAsync(cancellationToken);
        ArchiveVerification report = await archive.VerifyAsync(head, cancellationToken);
        List<ArchivedEvent> events = [];
        await foreach (ArchivedEvent item in archive.ReadAllAsync(cancellationToken))
        {
            events.Add(item);
        }

        Assert.Equal((1, 3L), (first.Segments, first.Events));
        Assert.Equal(0, idle.Segments);
        Assert.Equal((1, 2L), (second.Segments, second.Events));
        Assert.True(report.Intact);
        Assert.True(report.AnchorVerified);
        Assert.Equal(head.Hash, report.HeadHash);
        Assert.Equal(5, archive.ArchivedThroughSequence());
        Assert.Equal([1L, 2, 3, 4, 5], events.Select(item => item.Sequence));
        Assert.Equal("""{"eventId":"event-2"}""", events[1].Payload);
    }

    [Fact]
    public async Task Verify_DetectsAlteredSegmentEvenWhenManifestDigestIsUpdated()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 3, clock, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        string segment = Path.Combine(ArchivePath(directory), "segment-000000000001.jsonl.gz");
        string manifest = Path.Combine(ArchivePath(directory), "segment-000000000001.manifest.json");

        string[] lines = ReadSegment(segment);
        string forged = lines[1].Replace("event-2", "forged", StringComparison.Ordinal);
        Assert.NotEqual(lines[1], forged);
        lines[1] = forged;
        WriteSegment(segment, lines);
        ArchiveVerification digestOnly = await archive.VerifyAsync(cancellationToken: cancellationToken);

        JsonObject document = JsonNode.Parse(File.ReadAllText(manifest))!.AsObject();
        document["segmentSha256"] = $"sha256:{Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(segment)))}";
        File.WriteAllText(manifest, document.ToJsonString());
        ArchiveVerification rewritten = await archive.VerifyAsync(cancellationToken: cancellationToken);

        Assert.Equal("segment-digest-mismatch", digestOnly.BreakReason);
        Assert.Equal("chain-broken", rewritten.BreakReason);
    }

    [Fact]
    public async Task Verify_ReportsMissingSegmentsAndAnchorFailures()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 2, clock, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        LedgerHead head = await store.GetLedgerHeadAsync(cancellationToken);

        ArchiveVerification wrongHash = await archive.VerifyAsync(head with { Hash = new string('0', 64) }, cancellationToken);
        ArchiveVerification beyond = await archive.VerifyAsync(head with { Sequence = head.Sequence + 10 }, cancellationToken);
        await EnqueueAsync(store, 3, 3, clock, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000001.manifest.json"));
        ArchiveVerification missingFirst = await archive.VerifyAsync(cancellationToken: cancellationToken);
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000003.manifest.json"));
        ArchiveVerification empty = await archive.VerifyAsync(cancellationToken: cancellationToken);

        Assert.Equal("anchor-mismatch", wrongHash.BreakReason);
        Assert.Equal("anchor-missing", beyond.BreakReason);
        // Without the first manifest the archive starts at 3 with an unproven predecessor:
        // the stored previous hash still chains, so only an anchor at 1 or 2 would expose it.
        Assert.True(missingFirst.Intact);
        Assert.Equal(3, missingFirst.FirstSequence);
        Assert.Equal("archive-empty", empty.BreakReason);
    }

    [Fact]
    public async Task Archive_RewritesSegmentLeftWithoutManifestByCrash()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 2, clock, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000001.manifest.json"));
        await EnqueueAsync(store, 3, 3, clock, cancellationToken);

        ArchiveRunResult recovered = await archive.ArchiveAsync(store, cancellationToken);
        ArchiveVerification report = await archive.VerifyAsync(cancellationToken: cancellationToken);

        Assert.Equal(3, recovered.Events);
        Assert.True(report.Intact);
        Assert.Equal(3, report.VerifiedEvents);
    }

    [Fact]
    public async Task Retention_PurgesOnlyArchivedEventsAndArchiveResumesAfterCompaction()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 4, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        await EnqueueAsync(store, 5, 6, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        clock.Advance(TimeSpan.FromDays(10));

        int purged = await store.PurgeDeliveredAsync(
            clock.UtcNow, 100, archive.ArchivedThroughSequence(), cancellationToken);
        ArchiveRunResult resumed = await archive.ArchiveAsync(store, cancellationToken);
        int rest = await store.PurgeDeliveredAsync(
            clock.UtcNow, 100, archive.ArchivedThroughSequence(), cancellationToken);
        LedgerVerification ledger = await store.VerifyLedgerAsync(cancellationToken);
        ArchiveVerification report = await archive.VerifyAsync(await store.GetLedgerHeadAsync(cancellationToken), cancellationToken);

        Assert.Equal(4, purged);
        Assert.Equal(2, resumed.Events);
        Assert.Equal(2, rest);
        Assert.True(ledger.Intact);
        Assert.True(report.Intact);
        Assert.Equal(6, report.VerifiedEvents);
    }

    [Fact]
    public async Task Archive_StartsAfterEarlierPurgeFromTheRecordedLedgerHash()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        await EnqueueAsync(store, 1, 3, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        clock.Advance(TimeSpan.FromDays(10));
        await store.PurgeDeliveredAsync(clock.UtcNow, 100, cancellationToken);
        await EnqueueAsync(store, 4, 5, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);

        ArchiveRunResult result = await archive.ArchiveAsync(store, cancellationToken);
        ArchiveVerification report = await archive.VerifyAsync(await store.GetLedgerHeadAsync(cancellationToken), cancellationToken);

        Assert.Equal(2, result.Events);
        Assert.True(report.Intact);
        Assert.Equal(4, report.FirstSequence);
    }

    internal static async Task DeliverAllAsync(SqliteEventStore store, CancellationToken cancellationToken)
    {
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(100, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredBatchAsync(
            [.. leased.Select(item => item.EventId)],
            "test-ack",
            leased.ToDictionary(item => item.EventId, item => item.LeaseToken!),
            cancellationToken);
    }

    internal static string[] ReadSegment(string path)
    {
        using FileStream file = File.OpenRead(path);
        using GZipStream gzip = new(file, CompressionMode.Decompress);
        using StreamReader reader = new(gzip, Encoding.UTF8);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }

    internal static void WriteSegment(string path, string[] lines)
    {
        using FileStream file = File.Create(path);
        using GZipStream gzip = new(file, CompressionLevel.Optimal);
        using StreamWriter writer = new(gzip, new UTF8Encoding(false));
        foreach (string line in lines)
        {
            writer.Write(line);
            writer.Write('\n');
        }
    }

    internal static async Task EnqueueAsync(
        SqliteEventStore store,
        int first,
        int last,
        FakeClock clock,
        CancellationToken cancellationToken)
    {
        for (int index = first; index <= last; index++)
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            await store.EnqueueAsync(
                new QueuedEvent(
                    $"event-{index}",
                    $"sha256:event-{index}",
                    $$"""{"eventId":"event-{{index}}"}""",
                    clock.UtcNow),
                cancellationToken);
        }
    }

    internal static string ArchivePath(TemporaryDirectory directory) => Path.Combine(directory.Path, "archive");

    internal static async Task<SqliteEventStore> CreateStoreAsync(
        TemporaryDirectory directory,
        FakeClock clock,
        CancellationToken cancellationToken)
    {
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        return store;
    }
}

/// <summary>
/// A C#-written archive pinned for the Rust port
/// (<c>rust/crates/bower-persistence/tests/fixtures/archive-csharp</c>): both runtimes must
/// verify it. Set <c>BOWER_ARCHIVE_VECTOR_OUTPUT</c> to a directory to regenerate.
/// </summary>
public sealed class QueueArchiveParityTests
{
    public const string AnchorSequence = "4";

    [Fact]
    public async Task CSharpArchiveFixture_Verifies()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        if (Environment.GetEnvironmentVariable("BOWER_ARCHIVE_VECTOR_OUTPUT") is { Length: > 0 } output)
        {
            using TemporaryDirectory directory = new();
            FakeClock clock = new(TestEvents.Now);
            SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
            await store.InitializeAsync(cancellationToken);
            QueueArchive writer = new(output, "collector-parity", clock);
            string[] payloads =
            [
                "{\"eventId\":\"a1\",\"note\":\"plain\"}",
                "{\"eventId\":\"a2\",\"note\":\"zoë 用户 \\\"quoted\\\" \\\\ back\"}",
                "{\"eventId\":\"a3\",\"note\":\"\u2028 line separator\"}"
            ];
            for (int index = 0; index < payloads.Length; index++)
            {
                clock.Advance(TimeSpan.FromMilliseconds(1234.5678));
                await store.EnqueueAsync(new QueuedEvent($"a{index + 1}", $"sha256:a{index + 1}", payloads[index], clock.UtcNow), cancellationToken);
            }

            await writer.ArchiveAsync(store, cancellationToken);
            clock.Advance(TimeSpan.FromSeconds(1));
            await store.EnqueueAsync(new QueuedEvent("a4", "sha256:a4", """{"eventId":"a4"}""", clock.UtcNow), cancellationToken);
            await writer.ArchiveAsync(store, cancellationToken);
            LedgerHead head = await store.GetLedgerHeadAsync(cancellationToken);
            File.WriteAllText(Path.Combine(output, "anchor.txt"), $"{head.Sequence}:{head.Hash}\n");
        }

        string fixture = Path.Combine(AppContext.BaseDirectory, "persistence-vectors", "archive-csharp");
        string[] anchor = File.ReadAllText(Path.Combine(fixture, "anchor.txt")).Trim().Split(':');
        QueueArchive archive = new(fixture, "verifier");
        ArchiveVerification report = await archive.VerifyAsync(
            new LedgerHead(long.Parse(anchor[0], System.Globalization.CultureInfo.InvariantCulture), anchor[1]),
            cancellationToken);

        Assert.Equal(AnchorSequence, anchor[0]);
        Assert.True(report.Intact, report.BreakReason);
        Assert.True(report.AnchorVerified);
        Assert.Equal(2, report.Segments);
        Assert.Equal(4, report.VerifiedEvents);
    }
}
