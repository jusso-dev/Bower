using Bower.Abstractions;
using Bower.Persistence;

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
