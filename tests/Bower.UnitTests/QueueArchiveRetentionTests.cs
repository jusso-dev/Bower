using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Persistence;
using Microsoft.Extensions.Logging;
using static Bower.UnitTests.QueueArchiveTests;

namespace Bower.UnitTests;

/// <summary>
/// Retention purges only rows a verified archive of this queue covers (issue #66), and
/// archive writers exclude each other through the shared writer lock (issue #67).
/// </summary>
public sealed class QueueArchiveRetentionTests
{
    [Fact]
    public async Task Retention_KeepsRowsWhenASegmentIsDeleted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await ArchiveDeliveredAsync(store, archive, 1, 4, clock, cancellationToken);
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000001.jsonl.gz"));
        clock.Advance(TimeSpan.FromDays(10));
        RecordingLogger<QueueRetentionJob> logger = new();

        await RetentionJob(store, clock, archive, logger).RunAsync(cancellationToken);
        ArchiveCoverage coverage = await archive.VerifyCoverageAsync(store, cancellationToken);

        Assert.Equal(4, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.False(coverage.Verified);
        Assert.Equal("segment-missing", coverage.Reason);
        string evidence = Assert.Single(logger.Messages);
        Assert.Contains("segment-missing", evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("eventId", evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Retention_KeepsRowsWhenASegmentIsCorrupted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await ArchiveDeliveredAsync(store, archive, 1, 4, clock, cancellationToken);
        string segment = Path.Combine(ArchivePath(directory), "segment-000000000001.jsonl.gz");
        string[] lines = ReadSegment(segment);
        lines[0] = lines[0].Replace("event-1", "forged1", StringComparison.Ordinal);
        WriteSegment(segment, lines);
        clock.Advance(TimeSpan.FromDays(10));

        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        ArchiveCoverage coverage = await archive.VerifyCoverageAsync(store, cancellationToken);

        Assert.Equal(4, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.Equal("segment-digest-mismatch", coverage.Reason);
    }

    [Fact]
    public async Task Retention_RefusesAForeignArchiveWithOverlappingSequences()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TemporaryDirectory foreignDirectory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        SqliteEventStore foreign = await CreateStoreAsync(foreignDirectory, clock, cancellationToken);
        await EnqueueAsync(store, 1, 4, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        // A different queue with more events written into this collector's archive path.
        await EnqueueAsync(foreign, 101, 106, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await archive.ArchiveAsync(foreign, cancellationToken);
        clock.Advance(TimeSpan.FromDays(10));

        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        ArchiveCoverage coverage = await archive.VerifyCoverageAsync(store, cancellationToken);

        Assert.True((await archive.VerifyAsync(cancellationToken: cancellationToken)).Intact);
        Assert.Equal(4, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.Equal("lineage-mismatch", coverage.Reason);
    }

    [Fact]
    public async Task Retention_ProtectsRowsBelowAnArchiveThatLostItsFirstManifest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await ArchiveDeliveredAsync(store, archive, 1, 2, clock, cancellationToken);
        await ArchiveDeliveredAsync(store, archive, 3, 4, clock, cancellationToken);
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000001.manifest.json"));
        clock.Advance(TimeSpan.FromDays(10));

        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        ArchiveCoverage coverage = await archive.VerifyCoverageAsync(store, cancellationToken);

        Assert.Equal(4, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.Equal("archive-starts-above-retained", coverage.Reason);
        Assert.Equal(3, coverage.FirstSequence);
    }

    [Fact]
    public async Task Retention_PurgesVerifiedAcknowledgedRowsOnlyAndNoticesLaterCorruption()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 5, clock, cancellationToken);
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(4, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredAsync("event-1", "ack-1", LeaseTestClaims.Token(leased, "event-1"), cancellationToken);
        await store.MarkDeliveredAsync("event-2", "ack-2", LeaseTestClaims.Token(leased, "event-2"), cancellationToken);
        await store.MarkDeadLetteredAsync("event-3", "bad", LeaseTestClaims.Token(leased, "event-3"), cancellationToken);
        await store.MarkRetryingAsync("event-4", "busy", clock.UtcNow.AddDays(30), LeaseTestClaims.Token(leased, "event-4"), cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
        clock.Advance(TimeSpan.FromDays(10));

        ArchiveCoverage coverage = await archive.VerifyCoverageAsync(store, cancellationToken);
        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        QueueSnapshot afterPurge = await store.GetSnapshotAsync(cancellationToken);

        Assert.True(coverage.Verified, coverage.Reason);
        Assert.Equal((1L, 5L), (coverage.FirstSequence, coverage.ThroughSequence));
        Assert.Equal(0, afterPurge.Delivered);
        Assert.Equal((1L, 1L, 1L), (afterPurge.DeadLettered, afterPurge.Retrying, afterPurge.Queued));
        Assert.True((await store.VerifyLedgerAsync(cancellationToken)).Intact);

        // The cached verification must notice a segment changed after it was verified.
        await ArchiveDeliveredAsync(store, archive, 6, 7, clock, cancellationToken);
        Assert.True((await archive.VerifyCoverageAsync(store, cancellationToken)).Verified);
        string segment = Path.Combine(ArchivePath(directory), "segment-000000000006.jsonl.gz");
        string[] lines = ReadSegment(segment);
        lines[1] = lines[1].Replace("event-7", "forged7", StringComparison.Ordinal);
        WriteSegment(segment, lines);
        clock.Advance(TimeSpan.FromDays(10));

        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);

        Assert.Equal(3, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.Equal("segment-digest-mismatch", (await archive.VerifyCoverageAsync(store, cancellationToken)).Reason);
    }

    [Fact]
    public async Task Retention_AfterCrashBeforeManifestPurgesOnlyCommittedCoverageThenRecovers()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await ArchiveDeliveredAsync(store, archive, 1, 2, clock, cancellationToken);
        await ArchiveDeliveredAsync(store, archive, 3, 4, clock, cancellationToken);
        // Crash after the segment was published, before its manifest: an uncommitted orphan,
        // plus temporary files a crashed writer left behind.
        File.Delete(Path.Combine(ArchivePath(directory), "segment-000000000003.manifest.json"));
        File.WriteAllText(Path.Combine(ArchivePath(directory), "segment-000000000003.manifest.json.0123.tmp"), "{");
        File.WriteAllText(Path.Combine(ArchivePath(directory), "segment-000000000003.jsonl.gz.tmp"), "partial");
        clock.Advance(TimeSpan.FromDays(10));

        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        long retained = (await store.GetSnapshotAsync(cancellationToken)).Delivered;
        ArchiveRunResult recovered = await archive.ArchiveAsync(store, cancellationToken);
        await RetentionJob(store, clock, archive).RunAsync(cancellationToken);
        ArchiveVerification report = await archive.VerifyAsync(await store.GetLedgerHeadAsync(cancellationToken), cancellationToken);

        Assert.Equal(2, retained);
        Assert.Equal(2, recovered.Events);
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellationToken)).Delivered);
        Assert.True(report.Intact, report.BreakReason);
        Assert.Equal(4, report.VerifiedEvents);
        Assert.Empty(Directory.GetFiles(ArchivePath(directory), "*.tmp"));
    }

    [Fact]
    public async Task Archive_RefusesWhileAnotherWriterHoldsTheArchiveLock()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive archive = new(ArchivePath(directory), "collector-1", clock);
        await EnqueueAsync(store, 1, 2, clock, cancellationToken);
        Directory.CreateDirectory(ArchivePath(directory));

        // The same exclusive lock another process (either runtime) takes while it writes.
        using (new FileStream(
                   Path.Combine(ArchivePath(directory), QueueArchive.WriterLockFile),
                   FileMode.OpenOrCreate,
                   FileAccess.ReadWrite,
                   FileShare.None))
        {
            await Assert.ThrowsAsync<IOException>(() => archive.ArchiveAsync(store, cancellationToken));
            Assert.Empty(Directory.GetFiles(ArchivePath(directory), "segment-*"));
        }

        ArchiveRunResult result = await archive.ArchiveAsync(store, cancellationToken);
        Assert.Equal(2, result.Events);
    }

    [Fact]
    public async Task Archive_LosingConcurrentWriterLeavesCommittedSegmentByteIdentical()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        QueueArchive scheduled = new(ArchivePath(directory), "collector-1", clock);
        QueueArchive manual = new(ArchivePath(directory), "manual", clock);
        await EnqueueAsync(store, 1, 2, clock, cancellationToken);
        TaskCompletionSource captured = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        scheduled.BeforePublishAsync = async _ =>
        {
            captured.TrySetResult();
            await release.Task;
        };

        // The scheduled writer captures two rows and pauses before publishing.
        Task<ArchiveRunResult> first = scheduled.ArchiveAsync(store, cancellationToken);
        await captured.Task.WaitAsync(cancellationToken);
        await EnqueueAsync(store, 3, 5, clock, cancellationToken);
        // The manual writer would capture five rows from the same watermark; it must lose.
        await Assert.ThrowsAsync<IOException>(() => manual.ArchiveAsync(store, cancellationToken));
        release.SetResult();
        scheduled.BeforePublishAsync = null;
        ArchiveRunResult committed = await first;
        string segment = Path.Combine(ArchivePath(directory), "segment-000000000001.jsonl.gz");
        string manifest = Path.Combine(ArchivePath(directory), "segment-000000000001.manifest.json");
        byte[] segmentBytes = await File.ReadAllBytesAsync(segment, cancellationToken);
        byte[] manifestBytes = await File.ReadAllBytesAsync(manifest, cancellationToken);

        await EnqueueAsync(store, 6, 6, clock, cancellationToken);
        ArchiveRunResult later = await manual.ArchiveAsync(store, cancellationToken);
        ArchiveVerification report = await manual.VerifyAsync(await store.GetLedgerHeadAsync(cancellationToken), cancellationToken);

        // The winner published rows 1-2, then (still owning the archive) rows 3-5.
        Assert.Equal((2, 5L), (committed.Segments, committed.Events));
        Assert.Equal(1, later.Events);
        Assert.Equal(segmentBytes, await File.ReadAllBytesAsync(segment, cancellationToken));
        Assert.Equal(manifestBytes, await File.ReadAllBytesAsync(manifest, cancellationToken));
        Assert.True(report.Intact, report.BreakReason);
        Assert.Equal(6, report.VerifiedEvents);
    }

    [Fact]
    public async Task LedgerBoundaryAtOrBelow_ResolvesEntriesAndCompactedSegments()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        LedgerHead? empty = await store.GetLedgerBoundaryAtOrBelowAsync(5, cancellationToken);
        await EnqueueAsync(store, 1, 3, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        await EnqueueAsync(store, 4, 4, clock, cancellationToken);
        LedgerHead? entry = await store.GetLedgerBoundaryAtOrBelowAsync(10, cancellationToken);
        clock.Advance(TimeSpan.FromDays(10));
        await store.PurgeDeliveredAsync(clock.UtcNow, 100, cancellationToken);

        // Rows 1-3 are compacted into one segment ending at 3.
        LedgerHead? compacted = await store.GetLedgerBoundaryAtOrBelowAsync(2, cancellationToken);
        LedgerHead? end = await store.GetLedgerBoundaryAtOrBelowAsync(3, cancellationToken);

        Assert.Null(empty);
        Assert.Equal(4, entry!.Sequence);
        Assert.Equal(await store.GetLedgerHashAtAsync(4, cancellationToken), entry.Hash);
        Assert.Null(compacted);
        Assert.Equal(3, end!.Sequence);
        Assert.Equal(await store.GetLedgerHashAtAsync(3, cancellationToken), end.Hash);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.GetLedgerBoundaryAtOrBelowAsync(-1, cancellationToken));
    }

    private static async Task ArchiveDeliveredAsync(
        SqliteEventStore store,
        QueueArchive archive,
        int first,
        int last,
        FakeClock clock,
        CancellationToken cancellationToken)
    {
        await EnqueueAsync(store, first, last, clock, cancellationToken);
        await DeliverAllAsync(store, cancellationToken);
        await archive.ArchiveAsync(store, cancellationToken);
    }

    private static QueueRetentionJob RetentionJob(
        SqliteEventStore store,
        FakeClock clock,
        QueueArchive archive,
        ILogger<QueueRetentionJob>? logger = null) =>
        new(
            store,
            clock,
            new CollectorSettings
            {
                ListenUrl = "http://127.0.0.1:4319",
                QueuePath = "queue.db",
                PolicyDirectory = "policies",
                CollectorId = "collector-1"
            },
            logger ?? new RecordingLogger<QueueRetentionJob>(),
            archive);

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Messages.Add(formatter(state, exception));
            }
        }
    }
}
