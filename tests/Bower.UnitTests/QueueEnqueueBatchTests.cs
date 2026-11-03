using System.Text.Json;
using Bower.Abstractions;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

/// <summary>
/// Group commit (wecfix): one durable commit per Windows Event Log read instead of one per
/// event. Nothing is durable before the commit, a refused event leaves the rest, a failure or
/// crash before the commit rolls the whole read back, and the bookmark never passes an event
/// that is not durable.
/// </summary>
public sealed class QueueEnqueueBatchTests
{
    private const long OneMebibyte = 1024 * 1024;
    private const string Subscription = "app";

    [Fact]
    public async Task Batch_IsInvisibleUntilCommit_ThenDurableTogether_AndTheLedgerStaysIntact()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            for (int index = 1; index <= 5; index++)
            {
                Assert.True((await store.EnqueueAsync(Event(index), cancellation)).Enqueued);
            }

            Assert.True((await store.EnqueueAsync(Event(3), cancellation)).Duplicate);
            Assert.Equal(5, batch.Pending);
            // Another connection sees nothing yet (WAL readers see the last commit).
            Assert.Equal(0, await Count(path));
            await batch.CommitAsync(cancellation);
        }

        Assert.Equal(5, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
        Assert.Equal(5, (await store.GetLedgerHeadAsync(cancellation)).Sequence);
    }

    [Fact]
    public async Task UncommittedBatch_RollsBackOnDisposeAndAcrossACrash()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        await store.EnqueueAsync(Event(1), cancellation);

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(2), cancellation);
            await store.EnqueueAsync(Event(3), cancellation);
            // "Crash": the batch is abandoned without a commit.
        }

        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = await Store(path, 64 * OneMebibyte);
        Assert.Equal(1, await Count(path));
        Assert.True((await restarted.VerifyLedgerAsync(cancellation)).Intact);
        // The same events enqueue normally afterwards; nothing was half-written.
        Assert.True((await restarted.EnqueueAsync(Event(2), cancellation)).Enqueued);
        Assert.Equal(2, (await restarted.GetLedgerHeadAsync(cancellation)).Sequence);
    }

    [Fact]
    public async Task RefusedOrConflictingEvent_RollsBackOnlyItself()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, OneMebibyte);

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            // Same id, different content: an identity conflict, not a duplicate.
            await Assert.ThrowsAsync<EventIdentityConflictException>(() => store.EnqueueAsync(
                new QueuedEvent("e1", "sha256:other", """{"eventId":"e1","other":true}""", TestEvents.Now), cancellation));
            // Larger than the logical cap: refused as backpressure.
            await Assert.ThrowsAsync<QueueCapacityExceededException>(() => store.EnqueueAsync(Event(2, 2 * (int)OneMebibyte), cancellation));
            await store.EnqueueAsync(Event(3), cancellation);
            await batch.CommitAsync(cancellation);
        }

        Assert.Equal(2, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task OnlyTheJoinedFlowIsBatched_OtherWritersWaitForTheCommit()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        Task<EnqueueResult> other;
        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            // Started before Join: its own transaction, waiting for the batch's write lock.
            other = Task.Run(() => store.EnqueueAsync(Event(9), cancellation), cancellation);
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            await Task.Delay(100, cancellation);
            Assert.False(other.IsCompleted);
            await batch.CommitAsync(cancellation);
        }

        Assert.True((await other).Enqueued);
        Assert.Equal(2, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task Source_FailureBeforeTheBatchCommit_ReadsTheWholeBatchAgain_ExactlyOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        for (int record = 1; record <= 5; record++)
        {
            channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
        }

        BatchingStoreSink sink = new(store) { FailAtRecord = 4 };
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);

        WindowsEventChannelException failure = await Assert.ThrowsAsync<WindowsEventChannelException>(
            () => source.PollOnceAsync(Subscription, cancellation));
        Assert.Equal(WindowsEventChannelFailures.SubmitFailed, failure.Code);
        // Records 1-3 were enqueued in the batch but never committed: nothing is durable and
        // the bookmark did not move.
        Assert.Equal(0, await Count(path));
        Assert.Equal(0, source.Snapshot()[0].BookmarkRecordId);

        sink.FailAtRecord = null;
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(5, await Count(path));
        Assert.Equal(5, source.Snapshot()[0].BookmarkRecordId);
        Assert.Equal(1, sink.Commits);
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task Source_BackpressureMidBatch_CommitsThePrefixAndStopsBeforeTheRefusedEvent()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        for (int record = 1; record <= 5; record++)
        {
            channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
        }

        BatchingStoreSink sink = new(store) { RefuseFromRecord = 3 };
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);

        WindowsEventPollResult blocked = await source.PollOnceAsync(Subscription, cancellation);
        Assert.True(blocked.Backpressure);
        Assert.Equal(2, await Count(path));
        Assert.Equal(("backpressure", 2L), (source.Snapshot()[0].State, source.Snapshot()[0].BookmarkRecordId!.Value));

        sink.RefuseFromRecord = null;
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(5, await Count(path));
        Assert.Equal(5, source.Snapshot()[0].BookmarkRecordId);
    }

    [Fact]
    public async Task Source_CrashAfterTheBatchCommitBeforeTheBookmark_ReplaysIntoDeduplication()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        CrashingCursorStore cursors = new(await WindowsEventLogSourceTests.Cursors(directory));
        FakeWindowsEventChannelFactory channels = new();
        BatchingStoreSink sink = new(store);
        await using (WindowsEventLogSource source = new(Configuration(), sink, cursors, channels))
        {
            await source.PollOnceAsync(Subscription, cancellation); // first start: bookmark at 0
            for (int record = 1; record <= 4; record++)
            {
                channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
            }

            // The batch commits; the process "crashes" before the bookmark commit.
            cursors.FailNextCommits = 1;
            await Assert.ThrowsAsync<IOException>(() => source.PollOnceAsync(Subscription, cancellation));
        }

        Assert.Equal(4, await Count(path));
        await using WindowsEventLogSource restarted = new(Configuration(), sink, cursors, channels);
        await restarted.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(4, await Count(path));
        Assert.Equal(4, restarted.Snapshot()[0].BookmarkRecordId);
        Assert.True(restarted.Snapshot()[0].Duplicates >= 1);
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    private static WindowsEventLogSourceConfiguration Configuration() =>
        new("bower.security/v1", "WindowsEventLogSource",
        [
            new WindowsEventSubscriptionOptions(Subscription, "Application", [1000], "pack", 0, null, ReadExisting: true,
                IncludeMessage: false, PollIntervalSeconds: 1, BatchSize: 64)
        ]);

    private static async Task<SqliteEventStore> Store(string path, long maximumBytes)
    {
        SqliteEventStore store = new(path, maximumBytes, new FakeClock(TestEvents.Now));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        return store;
    }

    private static QueuedEvent Event(int index, int padding = 64) =>
        new($"e{index}", $"sha256:e{index}", $$"""{"eventId":"e{{index}}","pad":"{{new string('p', padding)}}"}""", TestEvents.Now);

    private static async Task<long> Count(string path)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM queue_events_v5;";
        return (long)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    /// <summary>The collector's batching sink over a real queue, with scripted failures.</summary>
    private sealed class BatchingStoreSink(SqliteEventStore store) : IWindowsEventSink, IWindowsEventBatchSink
    {
        public long? FailAtRecord { get; set; }

        public long? RefuseFromRecord { get; set; }

        public int Commits { get; private set; }

        public async ValueTask<WindowsEventSubmitOutcome> SubmitAsync(
            WindowsEventSubscriptionOptions subscription, string record, CancellationToken cancellationToken)
        {
            using JsonDocument document = JsonDocument.Parse(record);
            string id = document.RootElement.GetProperty("id").GetString()!;
            long recordId = long.Parse(document.RootElement.GetProperty("recordId").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            if (recordId == FailAtRecord)
            {
                throw new InvalidOperationException("sink failure");
            }

            if (recordId >= RefuseFromRecord)
            {
                return WindowsEventSubmitOutcome.Unavailable;
            }

            EnqueueResult result = await store.EnqueueAsync(new QueuedEvent(id, "sha256:" + id, record, TestEvents.Now), cancellationToken);
            return result.Duplicate ? WindowsEventSubmitOutcome.Duplicate : WindowsEventSubmitOutcome.Queued;
        }

        public async ValueTask<IWindowsEventBatch> BeginBatchAsync(CancellationToken cancellationToken) =>
            new Batch(this, await store.BeginEnqueueBatchAsync(cancellationToken));

        private sealed class Batch(BatchingStoreSink owner, QueueEnqueueBatch batch) : IWindowsEventBatch
        {
            public void Join() => batch.Join();

            public async Task CommitAsync(CancellationToken cancellationToken)
            {
                await batch.CommitAsync(cancellationToken);
                owner.Commits++;
            }

            public ValueTask DisposeAsync() => batch.DisposeAsync();
        }
    }
}
