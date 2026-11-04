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
    public async Task CommittedBatch_ObserverFailureDoesNotChangeCommitOrSkipLaterObservers()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        int observed = 0;

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            QueueEnqueueBatch.WhenDurable(store, () => throw new InvalidOperationException("observer"));
            QueueEnqueueBatch.WhenDurable(store, () => observed++);
            Assert.True(await batch.CommitAsync(cancellation));
        }

        Assert.Equal(1, observed);
        Assert.Equal(1, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task RefusedCommit_ReportsReasonAndDoesNotRunDurableObservers()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);
        List<string> reasons = [];
        int observed = 0;

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            QueueEnqueueBatch.WhenDurable(store, () => observed++);
            QueueEnqueueBatch.WhenRefused(store, reason => reasons.Add(reason.Reason));
            Assert.False(await batch.CommitAsync(cancellation));
        }

        Assert.Equal([QueueCapacityReasons.Queue], reasons);
        Assert.Equal(0, observed);
        Assert.Equal(0, await Count(path));
    }

    [Fact]
    public async Task RefusedCommit_OnCriticalVolumeReportsStorageFull()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * OneMebibyte * 1024, 20 * OneMebibyte * 1024);
        SqliteEventStore store = new(path, 64 * OneMebibyte, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(cancellation);
        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);
        List<string> reasons = [];

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            QueueEnqueueBatch.WhenRefused(store, reason => reasons.Add(reason.Reason));
            probe.FreeBytes = 10 * OneMebibyte;
            Assert.False(await batch.CommitAsync(cancellation));
        }

        Assert.Equal([QueueCapacityReasons.StorageFull], reasons);
        Assert.Equal(0, await Count(path));
    }

    [Fact]
    public async Task SqliteWholeTransactionRollback_MarksBatchBrokenAndDiscardsPendingWork()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        // SQLite itself aborts the entire transaction during the second insert, as opposed to
        // the commit fault seam (which raises before CommitAsync enters SQLite).
        await using (SqliteConnection setup = new($"Data Source={path};Pooling=False"))
        {
            await setup.OpenAsync(cancellation);
            await using SqliteCommand trigger = setup.CreateCommand();
            trigger.CommandText = """
                CREATE TRIGGER abort_batch BEFORE INSERT ON queue_events_v5
                WHEN NEW.event_id = 'e2' BEGIN SELECT RAISE(ROLLBACK, 'test rollback'); END;
                """;
            await trigger.ExecuteNonQueryAsync(cancellation);
        }

        int observed = 0;
        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            QueueEnqueueBatch.WhenDurable(store, () => observed++);
            await Assert.ThrowsAsync<SqliteException>(() => store.EnqueueAsync(Event(2), cancellation));
            Assert.False(await batch.CommitAsync(cancellation));
        }

        Assert.Equal(0, observed);
        Assert.Equal(0, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task SqliteCommitFailure_DoesNotPublishOrPersistTheBatch()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        await using (SqliteConnection setup = new($"Data Source={path};Pooling=False"))
        {
            await setup.OpenAsync(cancellation);
            await using SqliteCommand schema = setup.CreateCommand();
            // The deferred foreign key makes SQLite's actual COMMIT fail, not a pre-commit hook.
            schema.CommandText = """
                CREATE TABLE test_parent(id INTEGER PRIMARY KEY);
                CREATE TABLE test_child(parent_id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
                CREATE TRIGGER fail_at_commit AFTER INSERT ON queue_events_v5
                BEGIN INSERT INTO test_child(parent_id) VALUES (1); END;
                """;
            await schema.ExecuteNonQueryAsync(cancellation);
        }

        int observed = 0;
        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            await store.EnqueueAsync(Event(1), cancellation);
            QueueEnqueueBatch.WhenDurable(store, () => observed++);
            await Assert.ThrowsAsync<SqliteException>(() => batch.CommitAsync(cancellation));
        }

        Assert.Equal(0, observed);
        Assert.Equal(0, await Count(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task AtomicCursor_RefusedRecordRollsBackSuppressionAndSignals_ThenRestartRetriesOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = new(path);
        await cursors.InitializeAsync(cancellation);
        SuppressionRequest suppression = new("policy", "1", "hash", "key", [], [], 3600, 1,
            "authentication", "failure", "application", "test", null);
        QueuedEvent first = Event(1) with { Suppression = suppression };
        QueuedEvent second = Event(2) with { Suppression = suppression };
        int published = 0;

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            batch.BeginRecord();
            Assert.True((await store.EnqueueAsync(first, cancellation)).Enqueued);
            batch.EndRecord(true);
            batch.BeginRecord();
            Assert.True((await store.EnqueueAsync(second, cancellation)).Suppressed);
            QueueEnqueueBatch.WhenDurable(store, () => published++);
            // A later privacy alert was refused: none of this record's changes may remain.
            batch.EndRecord(false);
            Assert.Equal(QueueBatchCursorResult.Committed,
                await batch.CommitWithCursorAsync(cursors, "wec", 0, "record-1", TestEvents.Now, cancellation));
        }

        Assert.Equal(0, published);
        Assert.Equal(0, await SuppressedCount(path));
        Assert.Equal("record-1", (await cursors.ReadAsync("wec", cancellation))!.Value);
        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore resumed = new(path);
        await resumed.InitializeAsync(cancellation);
        await using (QueueEnqueueBatch batch = await restarted.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            batch.BeginRecord();
            Assert.True((await restarted.EnqueueAsync(second, cancellation)).Suppressed);
            batch.EndRecord(true);
            Assert.Equal(QueueBatchCursorResult.Committed,
                await batch.CommitWithCursorAsync(resumed, "wec", 1, "record-2", TestEvents.Now, cancellation));
        }

        Assert.Equal(1, await SuppressedCount(path));
        Assert.Equal("record-2", (await resumed.ReadAsync("wec", cancellation))!.Value);
        Assert.Equal(1, await Count(path));
        Assert.True((await restarted.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task AtomicCursor_ConflictOrCommitRefusalRollsBackEventsAndCursor()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = new(path);
        await cursors.InitializeAsync(cancellation);
        Assert.True(await cursors.TryAdvanceAsync("wec", 0, "other", TestEvents.Now, cancellation));

        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            batch.BeginRecord();
            await store.EnqueueAsync(Event(1), cancellation);
            batch.EndRecord(true);
            Assert.Equal(QueueBatchCursorResult.Conflict,
                await batch.CommitWithCursorAsync(cursors, "wec", 0, "lost", TestEvents.Now, cancellation));
        }
        Assert.Equal(0, await Count(path));
        Assert.Equal("other", (await cursors.ReadAsync("wec", cancellation))!.Value);

        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);
        await using (QueueEnqueueBatch batch = await store.BeginEnqueueBatchAsync(cancellation))
        {
            batch.Join();
            batch.BeginRecord();
            await store.EnqueueAsync(Event(1), cancellation);
            batch.EndRecord(true);
            Assert.Equal(QueueBatchCursorResult.Refused,
                await batch.CommitWithCursorAsync(cursors, "wec", 1, "refused", TestEvents.Now, cancellation));
        }
        Assert.Equal(0, await Count(path));
        Assert.Equal("other", (await cursors.ReadAsync("wec", cancellation))!.Value);
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
        Assert.Equal(5, source.Snapshot()[0].Queued);
        Assert.Equal(1, sink.Commits);
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task Source_RefusedRecordAndRefusedBatch_CountsOneRetryForTheRead()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        for (int record = 1; record <= 3; record++)
        {
            channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
        }

        BatchingStoreSink sink = new(store) { RefuseFromRecord = 3 };
        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(1, source.Snapshot()[0].Retries);
        Assert.Equal(0, await Count(path));
        Assert.Equal(0, source.Snapshot()[0].BookmarkRecordId);

        store.BatchCommitFaultForTesting = null;
        sink.RefuseFromRecord = null;
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(3, await Count(path));
        Assert.Equal(3, source.Snapshot()[0].BookmarkRecordId);
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
    public async Task AtomicSource_RefusedSuppressedRecordRetriesAfterRestartWithoutDoubleCounting()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        for (int record = 1; record <= 3; record++)
        {
            channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
        }
        SuppressionRequest suppression = new("policy", "1", "hash", "key", [], [], 3600, 1,
            "authentication", "failure", "application", "test", null);
        BatchingStoreSink sink = new(store) { EnableAtomic = true, Suppression = suppression, RefuseAfterRecord = 2 };
        await using (WindowsEventLogSource source = new(Configuration(), sink, cursors, channels))
        {
            Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
            Assert.Equal(1, source.Snapshot()[0].BookmarkRecordId);
            Assert.Equal(0, await SuppressedCount(path));
        }

        sink.RefuseAfterRecord = null;
        SqliteConnection.ClearAllPools();
        await using (WindowsEventLogSource restarted = new(Configuration(), sink, cursors, channels))
        {
            Assert.False((await restarted.PollOnceAsync(Subscription, cancellation)).Backpressure);
            Assert.Equal(3, restarted.Snapshot()[0].BookmarkRecordId);
            Assert.Equal(2, restarted.Snapshot()[0].Suppressed);
        }
        Assert.Equal(2, await SuppressedCount(path));
        Assert.Equal(1, await Count(path));
        await using WindowsEventLogSource resumed = new(Configuration(), sink, cursors, channels);
        await resumed.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(2, await SuppressedCount(path));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task AtomicSource_CursorConflictRollsBackBatchAndRetriesFromWinningCursor()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        BatchingStoreSink sink = new(store) { EnableAtomic = true };
        sink.BeforeBegin = async token =>
        {
            sink.BeforeBegin = null;
            Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 1,
                WindowsEventBookmark.At("Application", 0).Serialize(), TestEvents.Now, token));
        };
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(1, source.Snapshot()[0].CursorConflicts);
        Assert.Equal(0, source.Snapshot()[0].Queued);
        Assert.Equal(0, await Count(path));
        Assert.Equal(2, (await cursors.ReadAsync("windows-eventlog:app", cancellation))!.Version);

        Assert.False((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(1, await Count(path));
        Assert.Equal(1, source.Snapshot()[0].BookmarkRecordId);
    }

    [Fact]
    public async Task AtomicSource_ResetBaselineSurvivesRefusalAndGapMovesForwardSafely()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        BatchingStoreSink sink = new(store) { EnableAtomic = true };
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);
        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        SourceCursorSnapshot baseline = (await cursors.ReadAsync("windows-eventlog:app", cancellation))!;
        Assert.Equal(0, WindowsEventBookmark.Deserialize(baseline.Value, "Application").RecordId);
        Assert.Equal(0, await Count(path));

        store.BatchCommitFaultForTesting = null;
        // The recreated channel has already grown past the old bookmark of 100.
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(101, source.Snapshot()[0].BookmarkRecordId);
        Assert.Equal(2, await Count(path));
        channels["Application"].Clear();
        channels["Application"].Add(WindowsEventFixtures.Event(110, 1000));
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(110, source.Snapshot()[0].BookmarkRecordId);
        Assert.True(source.Snapshot()[0].Gaps >= 1);
        Assert.Equal(3, await Count(path));
    }

    [Fact]
    public async Task AtomicSource_FailedResetBaselineRemainsLatchedWhileChannelGrows()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(100, WindowsEventBookmark.Deserialize(
            (await cursors.ReadAsync("windows-eventlog:app", cancellation))!.Value, "Application").RecordId);
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        await Execute(path, "DROP TRIGGER refuse_reposition;");

        Assert.False((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal([1L, 101L], channels["Application"].Returned);
        Assert.Equal(2, await Count(path));
        Assert.Equal(101, source.Snapshot()[0].BookmarkRecordId);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AtomicSource_CompetingCursorAfterFailedResetDoesNotSkipOrOverwrite(int cursorCase)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);

        await Execute(path, "DROP TRIGGER refuse_reposition;");
        string exactBaseline = WindowsEventBookmark.At("Application", 0).Serialize();
        string competing = cursorCase switch
        {
            0 => WindowsEventBookmark.At("Application", 101).Serialize(),
            1 => "invalid-bookmark",
            2 => " " + exactBaseline, // Equivalent JSON, but not the exact CAS value.
            _ => exactBaseline
        };
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 1, competing, TestEvents.Now, cancellation));
        if (cursorCase == 3)
        {
            // The same value more than one version later is not our known CAS result.
            Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 2, competing, TestEvents.Now, cancellation));
        }
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(0, await Count(path));
        Assert.Equal(competing, (await cursors.ReadAsync("windows-eventlog:app", cancellation))!.Value);
        long conflicts = source.Snapshot()[0].CursorConflicts;
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        Assert.Equal(conflicts, source.Snapshot()[0].CursorConflicts);
    }

    [Fact]
    public async Task Source_UnreconciledCursorRemainsUnhealthyAcrossTransientReadFailure()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore inner = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await inner.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        BusyCursorStore cursors = new(inner);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(), new BatchingStoreSink(store), cursors, channels)
        {
            RetryDelay = TimeSpan.FromMilliseconds(500),
            IsTransientStorageFailure = QueueStorageErrors.IsBusy
        };

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        await Execute(path, "DROP TRIGGER refuse_reposition;");
        Assert.True(await inner.TryAdvanceAsync("windows-eventlog:app", 1,
            WindowsEventBookmark.At("Application", 101).Serialize(), TestEvents.Now, cancellation));
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        WindowsEventSubscriptionStatus before = source.Snapshot()[0];
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, before.State);

        // A distinct channel failure is shown while it occurs, but does not resolve the
        // previously observed cursor conflict.
        channels["Application"].FailWith = WindowsEventChannelFailures.AccessDenied;
        WindowsEventChannelException denied = await Assert.ThrowsAsync<WindowsEventChannelException>(
            () => source.PollOnceAsync(Subscription, cancellation));
        Assert.Equal(WindowsEventChannelFailures.AccessDenied, denied.Code);
        Assert.Equal(WindowsEventChannelFailures.AccessDenied, source.Snapshot()[0].State);
        channels["Application"].FailWith = null;

        cursors.BusyReads = 1;
        await source.StartAsync(cancellation);
        WindowsEventSubscriptionStatus busy = await WindowsEventLogSourceTests.WaitFor(
            source, status => status.Retries >= before.Retries + 1, cancellation);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, busy.State);
        Assert.Equal(before.CursorConflicts, busy.CursorConflicts);
        WindowsEventSubscriptionStatus retried = await WindowsEventLogSourceTests.WaitFor(
            source, status => status.Retries >= before.Retries + 2, cancellation);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, retried.State);
        Assert.Equal(before.CursorConflicts, retried.CursorConflicts);
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(0, await Count(path));
    }

    [Fact]
    public async Task Source_ConflictedRepositionDoesNotTrustAReappearingOldCursor()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore inner = await WindowsEventLogSourceTests.Cursors(directory);
        string oldValue = WindowsEventBookmark.At("Application", 100).Serialize();
        Assert.True(await inner.TryAdvanceAsync("windows-eventlog:app", 0, oldValue, TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        SnapshotOverrideStore cursors = new(inner);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(), new BatchingStoreSink(store), cursors, channels);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        cursors.NextSnapshot = new SourceCursorSnapshot(WindowsEventBookmark.At("Application", 101).Serialize(), 2);
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        long conflicts = source.Snapshot()[0].CursorConflicts;
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        await Execute(path, "DROP TRIGGER refuse_reposition;");

        // Even if a later read reports the original cursor again, the intervening version
        // remains unexplained and must not be silently overwritten.
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        Assert.Equal(conflicts, source.Snapshot()[0].CursorConflicts);
        Assert.Equal(oldValue, (await inner.ReadAsync("windows-eventlog:app", cancellation))!.Value);
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(0, await Count(path));
    }

    [Fact]
    public async Task AtomicSource_DeletedCursorDuringPendingRepositionFailsClosed()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);

        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        await Execute(path, "DELETE FROM source_cursors WHERE SourceId = 'windows-eventlog:app';");
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        Assert.Null(await cursors.ReadAsync("windows-eventlog:app", cancellation));
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(0, await Count(path));
        long conflicts = source.Snapshot()[0].CursorConflicts;
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(WindowsEventChannelFailures.CursorUnreconciled, source.Snapshot()[0].State);
        Assert.Equal(conflicts, source.Snapshot()[0].CursorConflicts);
        Assert.Null(await cursors.ReadAsync("windows-eventlog:app", cancellation));
    }

    [Fact]
    public async Task AtomicSource_PendingGapRewindsIfChannelResetsBeforeBaselineSucceeds()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 10).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);

        // Before the pending gap baseline can be stored, the channel is cleared again.
        channels["Application"].Clear();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await Execute(path, "DROP TRIGGER refuse_reposition;");
        Assert.False((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal([1L], channels["Application"].Returned);
        Assert.Equal(1, source.Snapshot()[0].BookmarkRecordId);
        Assert.True(source.Snapshot()[0].Resets > 0);
        Assert.Equal(1, await Count(path));
    }

    [Fact]
    public async Task AtomicSource_PendingResetReportsNewGapWhileBaselineIsUnavailable()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 100).Serialize(), TestEvents.Now, cancellation));
        await Execute(path, """
            CREATE TRIGGER refuse_reposition BEFORE UPDATE ON source_cursors
            BEGIN SELECT RAISE(ABORT, 'cursor write refused'); END;
            """);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);
        Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        channels["Application"].Clear();
        channels["Application"].Add(WindowsEventFixtures.Event(50, 1000));
        await Execute(path, "DROP TRIGGER refuse_reposition;");

        Assert.False((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal([50L], channels["Application"].Returned);
        Assert.True(source.Snapshot()[0].Gaps > 0);
        Assert.Equal(50, source.Snapshot()[0].BookmarkRecordId);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Source_ExactBaselineAfterUncertainCommitResumesAndRechecksRange(bool resetAgain, bool throwAfterCommit)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore inner = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await inner.TryAdvanceAsync("windows-eventlog:app", 0,
            WindowsEventBookmark.At("Application", 10).Serialize(), TestEvents.Now, cancellation));
        UncertainCursorStore cursors = new(inner, throwAfterCommit);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        await using WindowsEventLogSource source = new(Configuration(), new BatchingStoreSink(store), cursors, channels);

        // The cursor CAS commits the gap baseline but its caller receives false.
        if (throwAfterCommit)
        {
            await Assert.ThrowsAsync<IOException>(() => source.PollOnceAsync(Subscription, cancellation));
        }
        else
        {
            Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        }
        SourceCursorSnapshot persisted = (await inner.ReadAsync("windows-eventlog:app", cancellation))!;
        Assert.Equal((2L, 100L), (persisted.Version,
            WindowsEventBookmark.Deserialize(persisted.Value, "Application").RecordId));
        if (resetAgain)
        {
            channels["Application"].Clear();
            channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        }

        Assert.False((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        Assert.Equal(resetAgain ? 1 : 101, source.Snapshot()[0].BookmarkRecordId);
        Assert.Equal([resetAgain ? 1L : 101L], channels["Application"].Returned);
        Assert.Equal("running", source.Snapshot()[0].State);
        Assert.Equal(1, await Count(path));
    }

    [Fact]
    public async Task AtomicSource_V1ReplayBaselineSurvivesBatchRefusalAndRestart()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0,
            new WindowsEventBookmark(1, "Application", 100).Serialize(), TestEvents.Now, cancellation));
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        store.BatchCommitFaultForTesting = () => new SqliteException("database full", 13);
        BatchingStoreSink sink = new(store) { EnableAtomic = true };
        await using (WindowsEventLogSource source = new(Configuration(), sink, cursors, channels))
        {
            Assert.True((await source.PollOnceAsync(Subscription, cancellation)).Backpressure);
        }
        WindowsEventBookmark baseline = WindowsEventBookmark.Deserialize(
            (await cursors.ReadAsync("windows-eventlog:app", cancellation))!.Value, "Application");
        Assert.Equal((2, 0L), (baseline.SchemaVersion, baseline.RecordId));
        store.BatchCommitFaultForTesting = null;
        channels["Application"].Add(WindowsEventFixtures.Event(101, 1000));
        await using WindowsEventLogSource restarted = new(Configuration(), sink, cursors, channels);
        await restarted.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(2, await Count(path));
        Assert.Equal(101, restarted.Snapshot()[0].BookmarkRecordId);
    }

    [Fact]
    public async Task AtomicSource_CatchesUpPastUnselectedEventsAndIdlePollDoesNotAdvanceVersion()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        channels["Application"].Add(WindowsEventFixtures.Event(3, 1001));
        await using WindowsEventLogSource source = new(Configuration(),
            new BatchingStoreSink(store) { EnableAtomic = true }, cursors, channels);

        await source.PollOnceAsync(Subscription, cancellation);
        SourceCursorSnapshot caughtUp = (await cursors.ReadAsync("windows-eventlog:app", cancellation))!;
        Assert.Equal(3, WindowsEventBookmark.Deserialize(caughtUp.Value, "Application").RecordId);
        Assert.Equal(1, await Count(path));
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(caughtUp, await cursors.ReadAsync("windows-eventlog:app", cancellation));
    }

    [Fact]
    public async Task AtomicSource_CancellationDuringRecordRollsBackTheWholeRead()
    {
        using CancellationTokenSource cancellation = new();
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = await Store(path, 64 * OneMebibyte);
        EfSourceCursorStore cursors = await WindowsEventLogSourceTests.Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        channels["Application"].Add(WindowsEventFixtures.Event(2, 1000));
        BatchingStoreSink sink = new(store) { EnableAtomic = true, AfterWrite = id => { if (id == 2) cancellation.Cancel(); } };
        await using WindowsEventLogSource source = new(Configuration(), sink, cursors, channels);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.PollOnceAsync(Subscription, cancellation.Token));
        Assert.Equal(0, await Count(path));
        SourceCursorSnapshot snapshot = (await cursors.ReadAsync("windows-eventlog:app", TestContext.Current.CancellationToken))!;
        Assert.Equal(0, WindowsEventBookmark.Deserialize(snapshot.Value, "Application").RecordId);
        sink.AfterWrite = null;
        await source.PollOnceAsync(Subscription, TestContext.Current.CancellationToken);
        Assert.Equal(2, await Count(path));
        Assert.Equal(2, source.Snapshot()[0].BookmarkRecordId);
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

    private static async Task<long> SuppressedCount(string path)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COALESCE(SUM(suppressed), 0) FROM suppression_windows;";
        return (long)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    private static async Task Execute(string path, string sql)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>Simulates a cursor CAS that commits, but whose caller sees a failure.</summary>
    private sealed class UncertainCursorStore(ISourceCursorStore inner, bool throwAfterCommit) : ISourceCursorStore
    {
        private bool firstAdvance = true;

        public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(sourceId, cancellationToken);

        public async Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value,
            DateTimeOffset updatedAt, CancellationToken cancellationToken = default)
        {
            bool advanced = await inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
            if (firstAdvance && advanced)
            {
                firstAdvance = false;
                if (throwAfterCommit)
                {
                    throw new IOException("Simulated lost cursor acknowledgement");
                }
                return false;
            }
            return advanced;
        }
    }

    private sealed class SnapshotOverrideStore(ISourceCursorStore inner) : ISourceCursorStore
    {
        public SourceCursorSnapshot? NextSnapshot { get; set; }

        public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default)
        {
            if (NextSnapshot is { } snapshot)
            {
                NextSnapshot = null;
                return Task.FromResult<SourceCursorSnapshot?>(snapshot);
            }
            return inner.ReadAsync(sourceId, cancellationToken);
        }

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value,
            DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
            inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
    }

    /// <summary>The collector's batching sink over a real queue, with scripted failures.</summary>
    private sealed class BatchingStoreSink(SqliteEventStore store) : IWindowsEventSink, IWindowsEventBatchSink
    {
        public bool EnableAtomic { get; set; }

        public Func<CancellationToken, Task>? BeforeBegin { get; set; }

        public Action<long>? AfterWrite { get; set; }

        public SuppressionRequest? Suppression { get; set; }

        public long? RefuseAfterRecord { get; set; }

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

            EnqueueResult result = await store.EnqueueAsync(new QueuedEvent(id, "sha256:" + id, record, TestEvents.Now,
                Suppression: Suppression), cancellationToken);
            AfterWrite?.Invoke(recordId);
            cancellationToken.ThrowIfCancellationRequested();
            if (recordId == RefuseAfterRecord)
            {
                // Simulate a later part of this record (such as its privacy alert) being refused.
                return WindowsEventSubmitOutcome.Unavailable;
            }
            return result.Duplicate ? WindowsEventSubmitOutcome.Duplicate
                : result.Suppressed ? WindowsEventSubmitOutcome.Suppressed : WindowsEventSubmitOutcome.Queued;
        }

        public async ValueTask<IWindowsEventBatch> BeginBatchAsync(CancellationToken cancellationToken)
        {
            if (BeforeBegin is { } before)
            {
                await before(cancellationToken);
            }
            return new Batch(this, await store.BeginEnqueueBatchAsync(cancellationToken));
        }

        private sealed class Batch(BatchingStoreSink owner, QueueEnqueueBatch batch) : IWindowsEventAtomicBatch
        {
            public void Join() => batch.Join();

            public async Task<bool> CommitAsync(CancellationToken cancellationToken)
            {
                bool committed = await batch.CommitAsync(cancellationToken);
                owner.Commits += committed ? 1 : 0;
                return committed;
            }

            public bool CanAdvanceCursor(ISourceCursorStore cursors) => owner.EnableAtomic && batch.CanAdvanceCursor(cursors);

            public void BeginRecord() => batch.BeginRecord();

            public void EndRecord(bool handled) => batch.EndRecord(handled);

            public async Task<WindowsEventAtomicCommit> CommitWithCursorAsync(
                ISourceCursorStore cursors, string sourceId, long expectedVersion, string value,
                DateTimeOffset updatedAt, CancellationToken cancellationToken)
            {
                QueueBatchCursorResult result = await batch.CommitWithCursorAsync(cursors, sourceId, expectedVersion, value, updatedAt, cancellationToken);
                owner.Commits += result == QueueBatchCursorResult.Committed ? 1 : 0;
                return result switch
                {
                    QueueBatchCursorResult.Committed => WindowsEventAtomicCommit.Committed,
                    QueueBatchCursorResult.Refused => WindowsEventAtomicCommit.Refused,
                    _ => WindowsEventAtomicCommit.Conflict
                };
            }

            public ValueTask DisposeAsync() => batch.DisposeAsync();
        }
    }
}
