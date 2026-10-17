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
