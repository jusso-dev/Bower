using System.Diagnostics;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

/// <summary>
/// Retention purges in short, bounded transactions (the 24-hour soak's hourly purge of about
/// 40,000 rows held the write lock long enough for sources and delivery to hit the busy
/// timeout). Ledger compaction is bounded by each purge and stays verifiable across restarts.
/// </summary>
public sealed class QueueRetentionBatchingTests
{
    private const long OneMebibyte = 1024 * 1024;

    [Fact]
    public async Task Purge_CompactsOnlyThroughThePurgedRows_SurvivesRestart_AndLaterPurgesMergeTheRuns()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, 64 * OneMebibyte, clock);
        await store.InitializeAsync(cancellation);
        for (int index = 1; index <= 9; index++)
        {
            await Enqueue(store, clock, index, cancellation);
        }

        // Acknowledge the newest three first, so the first purge (oldest acknowledgement
        // first) takes sequences 7-9 while 1-6 are still retained ahead of them.
        await Deliver(store, ["e7", "e8", "e9"], cancellation);
        clock.Advance(TimeSpan.FromMinutes(1));
        await Deliver(store, ["e1", "e2", "e3", "e4", "e5", "e6"], cancellation);
        clock.Advance(TimeSpan.FromDays(8));
        DateTimeOffset cutoff = clock.UtcNow.AddDays(-7);

        Assert.Equal(3, await store.PurgeDeliveredAsync(cutoff, 3, cancellation));
        Assert.Equal([(7L, 9L)], await Segments(path));
        Assert.Equal(6, await LedgerRows(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);

        // Crash and restart between purges: the ledger and its segments are durable state.
        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = new(path, 64 * OneMebibyte, clock);
        await restarted.InitializeAsync(cancellation);
        Assert.True((await restarted.VerifyLedgerAsync(cancellation)).Intact);

        Assert.Equal(3, await restarted.PurgeDeliveredAsync(cutoff, 3, cancellation));
        Assert.Equal([(1L, 3L), (7L, 9L)], await Segments(path));
        Assert.Equal(3, await restarted.PurgeDeliveredAsync(cutoff, 10, cancellation));
        // The scan reaches the last compacted segment, so the runs merge into one.
        Assert.Equal([(1L, 9L)], await Segments(path));
        Assert.Equal(0, await LedgerRows(path));
        Assert.True((await restarted.VerifyLedgerAsync(cancellation)).Intact);

        await Enqueue(restarted, clock, 10, cancellation);
        await Deliver(restarted, ["e10"], cancellation);
        clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(1, await restarted.PurgeDeliveredAsync(clock.UtcNow.AddDays(-7), 10, cancellation));
        Assert.Equal([(1L, 10L)], await Segments(path));
        LedgerVerification verification = await restarted.VerifyLedgerAsync(cancellation);
        Assert.True(verification.Intact);
        Assert.Equal(10, (await restarted.GetLedgerHeadAsync(cancellation)).Sequence);
    }

    [Fact]
    public async Task CorruptEntryBeforeThePurgedRows_IsRefusedAndNothingIsPurged()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, 64 * OneMebibyte, clock);
        await store.InitializeAsync(cancellation);
        for (int index = 1; index <= 6; index++)
        {
            await Enqueue(store, clock, index, cancellation);
        }

        await Deliver(store, ["e4", "e5", "e6"], cancellation);
        clock.Advance(TimeSpan.FromDays(8));
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellation);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE queue_ledger SET chain_hash = 'corrupt' WHERE sequence = 2;";
            await command.ExecuteNonQueryAsync(cancellation);
        }

        // Sequence 2 is inside the bounded scan (before the purged 4-6): refused, rolled back.
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.PurgeDeliveredAsync(clock.UtcNow.AddDays(-7), 10, cancellation));
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellation);
        Assert.Equal((3L, 3L), (snapshot.Retrying, snapshot.Delivered));
        Assert.Equal(0, await LedgerRows(path, purgedOnly: true));
        Assert.Empty(await Segments(path));
    }

    [Fact]
    public async Task RetentionJob_LargePurge_NeverHoldsWritersNearTheBusyTimeout()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, 512 * OneMebibyte, clock);
        await store.InitializeAsync(cancellation);
        const int rows = 3 * QueueRetentionJob.BatchSize + 200;
        for (int index = 1; index <= rows; index++)
        {
            await Enqueue(store, clock, index, cancellation);
            if (index % 500 == 0)
            {
                await Deliver(store, null, cancellation);
            }
        }

        await Deliver(store, null, cancellation);
        clock.Advance(TimeSpan.FromDays(8));

        // A source keeps writing while retention runs; every write must get the lock well
        // inside the 5-second busy timeout (here, under half of it).
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        TimeSpan slowest = TimeSpan.Zero;
        int written = 0;
        Task writer = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                long started = Stopwatch.GetTimestamp();
                await Enqueue(store, clock, rows + 1 + written, CancellationToken.None);
                TimeSpan elapsed = Stopwatch.GetElapsedTime(started);
                slowest = elapsed > slowest ? elapsed : slowest;
                written++;
                await Task.Delay(5, CancellationToken.None);
            }
        }, CancellationToken.None);

        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = path,
            PolicyDirectory = "policies",
            CollectorId = "collector-1"
        };
        List<TimeSpan> pauses = [];
        await new QueueRetentionJob(store, clock, settings, NullLogger<QueueRetentionJob>.Instance)
        {
            Pause = async (pause, token) => { pauses.Add(pause); await Task.Delay(pause, token); }
        }.RunAsync(cancellation);
        await stop.CancelAsync();
        await writer;

        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellation);
        Assert.Equal(0, snapshot.Delivered);
        Assert.Equal(written, snapshot.Queued);
        Assert.True(written > 0);
        Assert.True(slowest < TimeSpan.FromMilliseconds(2_500), $"slowest write {slowest.TotalMilliseconds} ms");
        Assert.Equal(0, await LedgerRows(path, purgedOnly: true));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
        // Routine expiry pauses after each full batch (three of 1,000, then 200).
        Assert.Equal([QueueRetentionJob.BatchPause, QueueRetentionJob.BatchPause, QueueRetentionJob.BatchPause], pauses);
    }

    private static Task<EnqueueResult> Enqueue(SqliteEventStore store, FakeClock clock, int index, CancellationToken cancellation) =>
        store.EnqueueAsync(
            new QueuedEvent($"e{index}", $"sha256:e{index}", $$"""{"eventId":"e{{index}}","pad":"{{new string('p', 256)}}"}""", clock.UtcNow),
            cancellation);

    /// <summary>Leases everything queued and acknowledges <paramref name="ids"/> (all when null); the rest go back by retry.</summary>
    private static async Task Deliver(SqliteEventStore store, IReadOnlyList<string>? ids, CancellationToken cancellation)
    {
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(1_000, TimeSpan.FromMinutes(1), cancellation);
        Dictionary<string, string> tokens = leased.ToDictionary(item => item.EventId, item => item.LeaseToken!, StringComparer.Ordinal);
        List<string> acknowledged = [.. leased.Select(item => item.EventId).Where(id => ids is null || ids.Contains(id))];
        if (acknowledged.Count > 0)
        {
            await store.MarkDeliveredBatchAsync(acknowledged, "ack", tokens, cancellation);
        }

        foreach (QueuedEvent item in leased.Where(item => !acknowledged.Contains(item.EventId)))
        {
            await store.MarkRetryingAsync(item.EventId, "later", DateTimeOffset.MinValue, item.LeaseToken, cancellation);
        }
    }

    private static async Task<List<(long Start, long End)>> Segments(string path)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT start_sequence, end_sequence FROM queue_ledger_segments ORDER BY start_sequence;";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        List<(long, long)> segments = [];
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            segments.Add((reader.GetInt64(0), reader.GetInt64(1)));
        }

        return segments;
    }

    private static async Task<long> LedgerRows(string path, bool purgedOnly = false)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = purgedOnly
            ? "SELECT count(*) FROM queue_ledger WHERE purged_at IS NOT NULL;"
            : "SELECT count(*) FROM queue_ledger;";
        return (long)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }
}
