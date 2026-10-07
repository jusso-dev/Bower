using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.UnitTests;

public sealed class QueueRetentionTests
{
    private const long OneMebibyte = 1024 * 1024;

    [Fact]
    public async Task Purge_RemovesOnlyAcknowledgedEventsPastRetention()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAsync(store, clock, "delivered-old", cancellationToken);
        await EnqueueAsync(store, clock, "dead-lettered", cancellationToken);
        await EnqueueAsync(store, clock, "retrying", cancellationToken);
        await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredAsync("delivered-old", "ack-1", cancellationToken);
        await store.MarkDeadLetteredAsync("dead-lettered", "bad", cancellationToken);
        await store.MarkRetryingAsync("retrying", "busy", clock.UtcNow.AddDays(30), cancellationToken);
        clock.Advance(TimeSpan.FromDays(8));
        await EnqueueAsync(store, clock, "queued", cancellationToken);
        await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredAsync("queued", "ack-2", cancellationToken);

        int purged = await store.PurgeDeliveredAsync(
            clock.UtcNow.AddDays(-7),
            100,
            cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(1, purged);
        Assert.Equal(1, snapshot.Delivered);
        Assert.Equal(1, snapshot.DeadLettered);
        Assert.Equal(1, snapshot.Retrying);
    }

    [Fact]
    public async Task Purge_NeverRemovesUndeliveredEvents()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAsync(store, clock, "queued", cancellationToken);
        await EnqueueAsync(store, clock, "uploading", cancellationToken);
        await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellationToken);
        clock.Advance(TimeSpan.FromDays(365));

        int purged = await store.PurgeDeliveredAsync(clock.UtcNow, 100, cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(0, purged);
        Assert.Equal(1, snapshot.Queued);
        Assert.Equal(1, snapshot.Uploading);
    }

    [Fact]
    public async Task Capacity_IgnoresDeliveredHistory()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        string large = new('x', 600 * 1024);
        await store.EnqueueAsync(
            new QueuedEvent("delivered", "sha256:delivered", $$"""{"v":"{{large}}"}""", clock.UtcNow),
            cancellationToken);
        await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeliveredAsync("delivered", "ack", cancellationToken);

        EnqueueResult second = await store.EnqueueAsync(
            new QueuedEvent("next", "sha256:next", $$"""{"v":"{{large}}"}""", clock.UtcNow),
            cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.True(second.Enqueued);
        Assert.True(snapshot.TotalBytes > OneMebibyte);
        Assert.True(snapshot.UndeliveredBytes < OneMebibyte);
    }

    [Fact]
    public async Task Capacity_RejectsWhenUndeliveredBytesWouldExceedLimit()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        string large = new('x', 600 * 1024);
        await store.EnqueueAsync(
            new QueuedEvent("first", "sha256:first", $$"""{"v":"{{large}}"}""", clock.UtcNow),
            cancellationToken);

        await Assert.ThrowsAsync<QueueCapacityExceededException>(() => store.EnqueueAsync(
            new QueuedEvent("second", "sha256:second", $$"""{"v":"{{large}}"}""", clock.UtcNow),
            cancellationToken));
    }

    [Fact]
    public async Task Capacity_HoldsUnderConcurrentEnqueue()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        string chunk = new('x', 100 * 1024);

        Task<bool>[] attempts = Enumerable.Range(0, 24)
            .Select(index => Task.Run(async () =>
            {
                try
                {
                    await store.EnqueueAsync(
                        new QueuedEvent(
                            $"event-{index}",
                            $"sha256:{index}",
                            $$"""{"v":"{{chunk}}"}""",
                            clock.UtcNow),
                        cancellationToken);
                    return true;
                }
                catch (QueueCapacityExceededException)
                {
                    return false;
                }
            }, cancellationToken))
            .ToArray();
        await Task.WhenAll(attempts);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.True(snapshot.UndeliveredBytes <= OneMebibyte);
        Assert.Contains(attempts, attempt => !attempt.Result);
    }

    [Fact]
    public async Task Maintain_PreservesEventState()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * OneMebibyte, clock);
        await store.InitializeAsync(cancellationToken);
        await EnqueueAsync(store, clock, "queued", cancellationToken);

        await store.MaintainAsync(cancellationToken);
        SqliteEventStore restarted = new(Path.Combine(directory.Path, "queue.db"), 10 * OneMebibyte, clock);
        await restarted.InitializeAsync(cancellationToken);
        QueueSnapshot snapshot = await restarted.GetSnapshotAsync(cancellationToken);

        Assert.Equal(1, snapshot.Queued);
    }

    private static Task<EnqueueResult> EnqueueAsync(
        SqliteEventStore store,
        FakeClock clock,
        string eventId,
        CancellationToken cancellationToken) =>
        store.EnqueueAsync(
            new QueuedEvent(eventId, $"sha256:{eventId}", $$"""{"eventId":"{{eventId}}"}""", clock.UtcNow),
            cancellationToken);
}
