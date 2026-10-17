using Bower.Abstractions;
using Bower.Persistence;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class SqliteEventStoreTests
{
    [Fact]
    public async Task Enqueue_DeduplicatesFingerprintAndKeepsOriginal()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        QueuedEvent first = new("event-1", "sha256:same", """{"eventId":"event-1"}""", clock.UtcNow);
        QueuedEvent duplicate =
            new("event-2", "sha256:same", """{"eventId":"event-2"}""", clock.UtcNow);

        EnqueueResult firstResult = await store.EnqueueAsync(first, cancellationToken);
        EnqueueResult duplicateResult = await store.EnqueueAsync(duplicate, cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.True(firstResult.Enqueued);
        Assert.True(duplicateResult.Duplicate);
        Assert.Equal(1, snapshot.Queued);
    }

    [Fact]
    public async Task Lease_SurvivesRestartAndExpiresForRecovery()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore firstStore = CreateStore(directory, clock);
        await firstStore.InitializeAsync(cancellationToken);
        await firstStore.EnqueueAsync(
            new QueuedEvent(
                "event-1",
                "sha256:one",
                """{"eventId":"event-1"}""",
                clock.UtcNow),
            cancellationToken);

        IReadOnlyList<QueuedEvent> firstLease = await firstStore.LeaseAsync(
            10,
            TimeSpan.FromSeconds(10),
            cancellationToken);
        clock.Advance(TimeSpan.FromSeconds(11));

        SqliteEventStore restartedStore = CreateStore(directory, clock);
        await restartedStore.InitializeAsync(cancellationToken);
        IReadOnlyList<QueuedEvent> recovered = await restartedStore.LeaseAsync(
            10,
            TimeSpan.FromSeconds(10),
            cancellationToken);

        Assert.Single(firstLease);
        Assert.Single(recovered);
        Assert.Equal("event-1", recovered[0].EventId);
        Assert.Equal(2, recovered[0].DeliveryAttempts);
    }

    [Fact]
    public async Task MarkDelivered_RequiresLeaseAndRetainsAcknowledgedRecord()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(
            new QueuedEvent(
                "event-1",
                "sha256:one",
                """{"eventId":"event-1"}""",
                clock.UtcNow),
            cancellationToken);

        await Assert.ThrowsAsync<InvalidQueueTransitionException>(
            () => store.MarkDeliveredAsync("event-1", "not-leased", cancellationToken));
        await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredAsync("event-1", "ama-spool:file-1", cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(0, snapshot.Queued);
        Assert.Equal(1, snapshot.Delivered);
    }

    [Fact]
    public async Task Initialize_RestrictsDatabasePermissionsOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * 1024 * 1024, new FakeClock(TestEvents.Now));

        await store.InitializeAsync(cancellationToken);

        UnixFileMode mode = File.GetUnixFileMode(path);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }

    [Fact]
    public async Task MarkDeliveredBatch_SettlesLeasedEventsAndReturnsTheRest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        foreach (string eventId in new[] { "leased-1", "leased-2", "queued" })
        {
            await store.EnqueueAsync(
                new QueuedEvent(eventId, $"sha256:{eventId}", $$"""{"eventId":"{{eventId}}"}""", clock.UtcNow),
                cancellationToken);
        }

        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(3, TimeSpan.FromMinutes(5), cancellationToken);
        await store.MarkRetryingAsync("queued", "test", clock.UtcNow.AddHours(1), cancellationToken);

        IReadOnlyList<string> notLeased = await store.MarkDeliveredBatchAsync(
            ["leased-1", "leased-2", "queued", "missing"],
            "ack-batch",
            cancellationToken);
        IReadOnlyList<string> empty = await store.MarkDeliveredBatchAsync([], "ack-batch", cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(3, leased.Count);
        Assert.Equal(["queued", "missing"], notLeased);
        Assert.Empty(empty);
        Assert.Equal(2, snapshot.Delivered);
        Assert.Equal(1, snapshot.Retrying);
        Assert.Equal(0, snapshot.Uploading);
        await Assert.ThrowsAsync<ArgumentException>(
            () => store.MarkDeliveredBatchAsync(["ok", " "], "ack", cancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(
            () => store.MarkDeliveredBatchAsync(["ok"], " ", cancellationToken));
        Assert.True((await store.VerifyLedgerAsync(cancellationToken)).Intact);
    }

    [Fact]
    public async Task MarkDeliveredBatch_IsDurableAcrossRestartAndIdempotentOnReplay()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        foreach (string eventId in new[] { "event-1", "event-2" })
        {
            await store.EnqueueAsync(
                new QueuedEvent(eventId, $"sha256:{eventId}", $$"""{"eventId":"{{eventId}}"}""", clock.UtcNow),
                cancellationToken);
        }

        await store.LeaseAsync(2, TimeSpan.FromMinutes(5), cancellationToken);
        Assert.Empty(await store.MarkDeliveredBatchAsync(["event-1", "event-2"], "ack-1", cancellationToken));

        // Restart: the committed batch survives, a replayed acknowledgement changes nothing,
        // and delivered events are never leased again.
        SqliteEventStore restarted = CreateStore(directory, clock);
        await restarted.InitializeAsync(cancellationToken);
        IReadOnlyList<string> replay = await restarted.MarkDeliveredBatchAsync(
            ["event-1", "event-2"],
            "ack-2",
            cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(10));
        IReadOnlyList<QueuedEvent> releasable = await restarted.LeaseAsync(10, TimeSpan.FromMinutes(5), cancellationToken);
        QueueSnapshot snapshot = await restarted.GetSnapshotAsync(cancellationToken);

        Assert.Equal(["event-1", "event-2"], replay);
        Assert.Empty(releasable);
        Assert.Equal(2, snapshot.Delivered);
        Assert.Equal(0, snapshot.Uploading);
        Assert.True((await restarted.VerifyLedgerAsync(cancellationToken)).Intact);
    }

    [Fact]
    public async Task Initialize_AddsCapacityIndexIdempotentlyAndKeepsData()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(
            new QueuedEvent("event-1", "sha256:one", """{"eventId":"event-1"}""", clock.UtcNow),
            cancellationToken);

        // Simulate a queue created before the index existed, then upgrade by restarting.
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand drop = connection.CreateCommand();
            drop.CommandText =
                "DROP INDEX ix_queue_events_state_bytes; DELETE FROM schema_history WHERE version = 4;";
            await drop.ExecuteNonQueryAsync(cancellationToken);
        }

        SqliteEventStore restarted = CreateStore(directory, clock);
        await restarted.InitializeAsync(cancellationToken);
        await restarted.InitializeAsync(cancellationToken);

        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand plan = connection.CreateCommand();
            plan.CommandText =
                "EXPLAIN QUERY PLAN SELECT COALESCE(SUM(payload_bytes), 0) FROM queue_events WHERE state IN (0, 1, 2, 4);";
            await using SqliteDataReader reader = await plan.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.Contains("COVERING INDEX ix_queue_events_state_bytes", reader.GetString(3), StringComparison.Ordinal);
        }

        QueueSnapshot snapshot = await restarted.GetSnapshotAsync(cancellationToken);
        Assert.Equal(1, snapshot.Queued);
        Assert.True((await restarted.VerifyLedgerAsync(cancellationToken)).Intact);

        // Corruption path: version 4 recorded but the index is missing. Start-up recreates it.
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand drop = connection.CreateCommand();
            drop.CommandText = "DROP INDEX ix_queue_events_state_bytes;";
            await drop.ExecuteNonQueryAsync(cancellationToken);
        }

        await CreateStore(directory, clock).InitializeAsync(cancellationToken);
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand check = connection.CreateCommand();
            check.CommandText =
                "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'ix_queue_events_state_bytes'), (SELECT COUNT(*) FROM schema_history WHERE version = 4);";
            await using SqliteDataReader reader = await check.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.Equal(1, reader.GetInt64(0));
            Assert.Equal(1, reader.GetInt64(1));
        }
    }

    [Fact]
    public async Task Enqueue_RejectsInvalidInputInsteadOfReportingDuplicate()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);

        // Previously INSERT OR IGNORE swallowed CHECK failures and reported Duplicate.
        QueuedEvent[] invalid =
        [
            new("", "sha256:empty-id", "{}", clock.UtcNow),
            new(" \t", "sha256:blank-id", "{}", clock.UtcNow),
            new(new string('x', 129), "sha256:long-id", "{}", clock.UtcNow),
            new("nul\0id", "sha256:nul-id", "{}", clock.UtcNow),
            new("\0", "sha256:nul-only", "{}", clock.UtcNow),
            new("blank-fingerprint", " ", "{}", clock.UtcNow),
            new("empty-payload", "sha256:empty-payload", "", clock.UtcNow),
            new("null-fingerprint", null!, "{}", clock.UtcNow),
            new("null-payload", "sha256:null-payload", null!, clock.UtcNow)
        ];
        foreach (QueuedEvent candidate in invalid)
        {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => store.EnqueueAsync(candidate, cancellationToken));
        }

        // The limit mirrors SQLite length(): 128 characters, not 128 UTF-16 code units.
        EnqueueResult longest = await store.EnqueueAsync(
            new QueuedEvent(new string('x', 128), "sha256:x128", "{}", clock.UtcNow),
            cancellationToken);
        EnqueueResult astral = await store.EnqueueAsync(
            new QueuedEvent(string.Concat(Enumerable.Repeat("\U0001F600", 128)), "sha256:astral", "{}", clock.UtcNow),
            cancellationToken);
        await Assert.ThrowsAsync<ArgumentException>(() => store.EnqueueAsync(
            new QueuedEvent(string.Concat(Enumerable.Repeat("\U0001F600", 129)), "sha256:astral-129", "{}", clock.UtcNow),
            cancellationToken));
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);
        LedgerVerification verification = await store.VerifyLedgerAsync(cancellationToken);

        Assert.True(longest.Enqueued);
        Assert.True(astral.Enqueued);
        Assert.Equal(2, snapshot.Queued);
        Assert.True(verification.Intact);
        Assert.Equal(2, verification.Entries);
    }

    [Fact]
    public async Task Enqueue_ConcurrentDuplicatesInsertExactlyOnce()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);

        // Half the writers reuse the event id, half reuse the fingerprint under a new id.
        EnqueueResult[] results = await Task.WhenAll(Enumerable.Range(0, 24).Select(index => Task.Run(
            () => store.EnqueueAsync(
                new QueuedEvent(
                    index % 2 == 0 ? "same" : $"other-{index}",
                    "sha256:same",
                    """{"eventId":"same"}""",
                    clock.UtcNow),
                cancellationToken),
            cancellationToken)));
        LedgerVerification verification = await store.VerifyLedgerAsync(cancellationToken);

        Assert.Equal(1, results.Count(result => result.Enqueued));
        Assert.Equal(23, results.Count(result => result.Duplicate));
        Assert.All(results, result => Assert.NotEqual(result.Enqueued, result.Duplicate));
        Assert.True(verification.Intact);
        Assert.Equal(1, verification.Entries);
    }

    [Fact]
    public async Task MarkFailedBatch_SettlesLeasedEventsAndReturnsTheRest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAllAsync(store, clock, ["retry", "dead", "delivered"], cancellationToken);
        await store.LeaseAsync(3, TimeSpan.FromMinutes(5), cancellationToken);
        await store.MarkDeliveredAsync("delivered", "ack", cancellationToken);
        DateTimeOffset retryAt = new(2026, 8, 30, 9, 0, 0, TimeSpan.FromHours(5.5));

        IReadOnlyList<string> notLeased = await store.MarkFailedBatchAsync(
            [
                new FailureSettlement("retry", "busy", retryAt),
                new FailureSettlement("dead", "azure-http-400", null),
                new FailureSettlement("delivered", "late", null),
                new FailureSettlement("missing", "late", retryAt),
                new FailureSettlement("retry", "twice", null)
            ],
            cancellationToken);
        IReadOnlyList<string> empty = await store.MarkFailedBatchAsync([], cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);
        IReadOnlyList<DeadLetterRecord> dead = await store.ListDeadLetteredAsync(10, cancellationToken);

        Assert.Equal(["delivered", "missing", "retry"], notLeased);
        Assert.Empty(empty);
        Assert.Equal((1L, 1L, 1L, 0L), (snapshot.Retrying, snapshot.DeadLettered, snapshot.Delivered, snapshot.Uploading));
        Assert.Equal("azure-http-400", Assert.Single(dead).FailureCode);
        await using (SqliteConnection connection = OpenRaw(directory))
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText =
                "SELECT next_attempt_at, last_failure_code, lease_until FROM queue_events WHERE event_id = 'retry';";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.Equal("2026-08-30T03:30:00.0000000+00:00", reader.GetString(0));
            Assert.Equal("busy", reader.GetString(1));
            Assert.True(reader.IsDBNull(2));
        }

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => store.MarkFailedBatchAsync([null!], cancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(
            () => store.MarkFailedBatchAsync([new FailureSettlement(" ", "code", null)], cancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(
            () => store.MarkFailedBatchAsync([new FailureSettlement("retry", "", retryAt)], cancellationToken));
        Assert.True((await store.VerifyLedgerAsync(cancellationToken)).Intact);
    }

    [Fact]
    public async Task SettlementBatches_RollBackCompletelyOnErrorAndRecoverAfterRestart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAllAsync(store, clock, ["a", "b", "poison"], cancellationToken);
        await store.LeaseAsync(3, TimeSpan.FromMinutes(5), cancellationToken);

        // Adversarial storage failure on the last row of each batch.
        await ExecuteRawAsync(
            directory,
            """
            CREATE TRIGGER fail_poison BEFORE UPDATE OF state ON queue_events
            WHEN NEW.event_id = 'poison'
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
            """,
            cancellationToken);

        await Assert.ThrowsAsync<SqliteException>(() => store.MarkFailedBatchAsync(
            [
                new FailureSettlement("a", "busy", clock.UtcNow.AddMinutes(1)),
                new FailureSettlement("b", "bad", null),
                new FailureSettlement("poison", "bad", null)
            ],
            cancellationToken));
        await Assert.ThrowsAsync<SqliteException>(
            () => store.MarkDeliveredBatchAsync(["a", "b", "poison"], "ack", cancellationToken));
        QueueSnapshot afterFailure = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal((3L, 0L, 0L, 0L), (afterFailure.Uploading, afterFailure.Retrying, afterFailure.DeadLettered, afterFailure.Delivered));

        // Restart after the failure: nothing was half-settled, every lease is reclaimed once it
        // expires (at-least-once) and the reclaimed events settle normally.
        await ExecuteRawAsync(directory, "DROP TRIGGER fail_poison;", cancellationToken);
        SqliteEventStore restarted = CreateStore(directory, clock);
        await restarted.InitializeAsync(cancellationToken);
        Assert.Empty(await restarted.LeaseAsync(10, TimeSpan.FromMinutes(5), cancellationToken));
        clock.Advance(TimeSpan.FromMinutes(6));
        IReadOnlyList<QueuedEvent> reclaimed = await restarted.LeaseAsync(10, TimeSpan.FromMinutes(5), cancellationToken);
        Assert.Equal(["a", "b", "poison"], reclaimed.Select(item => item.EventId).Order(StringComparer.Ordinal).ToArray());
        Assert.All(reclaimed, item => Assert.Equal(2, item.DeliveryAttempts));
        Assert.Empty(await restarted.MarkFailedBatchAsync(
            [new FailureSettlement("a", "busy", clock.UtcNow.AddMinutes(1)), new FailureSettlement("b", "bad", null)],
            cancellationToken));
        Assert.Empty(await restarted.MarkDeliveredBatchAsync(["poison"], "ack", cancellationToken));
        QueueSnapshot settled = await restarted.GetSnapshotAsync(cancellationToken);
        Assert.Equal((0L, 1L, 1L, 1L), (settled.Uploading, settled.Retrying, settled.DeadLettered, settled.Delivered));
        Assert.True((await restarted.VerifyLedgerAsync(cancellationToken)).Intact);
    }

    [Fact]
    public async Task VerifyLedger_ReadsOneSnapshotWhileEnqueuesCommit()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = CreateStore(directory, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAllAsync(store, clock, ["seed"], cancellationToken);

        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task writer = Task.Run(
            async () =>
            {
                for (int index = 0; index < 400 && !stop.IsCancellationRequested; index++)
                {
                    await store.EnqueueAsync(
                        new QueuedEvent($"e{index}", $"sha256:e{index}", $$"""{"n":{{index}}}""", clock.UtcNow),
                        cancellationToken);
                }
            },
            cancellationToken);

        List<LedgerIssue> issues = [];
        while (!writer.IsCompleted)
        {
            issues.AddRange((await store.VerifyLedgerAsync(cancellationToken)).Issues);
        }

        await writer;
        LedgerVerification final = await store.VerifyLedgerAsync(cancellationToken);

        Assert.Empty(issues);
        Assert.True(final.Intact);
        Assert.Equal(401, final.Entries);
    }

    private static async Task EnqueueAllAsync(
        SqliteEventStore store,
        FakeClock clock,
        string[] eventIds,
        CancellationToken cancellationToken)
    {
        foreach (string eventId in eventIds)
        {
            await store.EnqueueAsync(
                new QueuedEvent(eventId, $"sha256:{eventId}", $$"""{"eventId":"{{eventId}}"}""", clock.UtcNow),
                cancellationToken);
        }
    }

    private static SqliteConnection OpenRaw(TemporaryDirectory directory)
    {
        SqliteConnection connection = new($"Data Source={Path.Combine(directory.Path, "queue.db")};Pooling=False");
        connection.Open();
        return connection;
    }

    private static async Task ExecuteRawAsync(
        TemporaryDirectory directory,
        string sql,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = OpenRaw(directory);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SqliteEventStore CreateStore(
        TemporaryDirectory directory,
        FakeClock clock)
    {
        return new SqliteEventStore(
            Path.Combine(directory.Path, "queue.db"),
            10 * 1024 * 1024,
            clock);
    }
}
