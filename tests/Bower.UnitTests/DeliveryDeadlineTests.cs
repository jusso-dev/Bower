using Bower.Abstractions;
using Bower.Collector;
using Bower.Persistence;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class DeliveryDeadlineTests
{
    [Fact]
    public async Task Timeout_PreservesEventsAcrossRestartWithoutSpendingPoisonBudget()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManualTimeProvider clock = new(TestEvents.Now);
        SqliteEventStore store = await OpenAsync(directory, clock, token);
        await EnqueueAsync(store, clock, "timeout", token);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            AsyncOutput output = new(async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("Unreachable");
            });
            using QueueDeliveryWorker worker = Worker(store, output, clock);
            Task<int> delivery = worker.DeliverOnceAsync(token);
            await output.Started.Task.WaitAsync(TimeSpan.FromSeconds(10), token);
            clock.Advance(TimeSpan.FromSeconds(59));
            Assert.False(delivery.IsCompleted);
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal(1, await delivery.WaitAsync(TimeSpan.FromSeconds(10), token));
            QueueSnapshot snapshot = await store.GetSnapshotAsync(token);
            Assert.Equal((0L, 1L, 0L, 0L),
                (snapshot.Uploading, snapshot.Retrying, snapshot.Delivered, snapshot.DeadLettered));
            store = await OpenAsync(directory, clock, token);
            using QueueDeliveryWorker restarted = Worker(store, AcknowledgeAll(), clock);
            Assert.Equal(0, await restarted.DeliverOnceAsync(token));
            clock.Advance(TimeSpan.FromSeconds(30));
        }

        using QueueDeliveryWorker recovered = Worker(store, AcknowledgeAll(), clock);
        Assert.Equal(1, await recovered.DeliverOnceAsync(token));
        Assert.Equal(1, (await store.GetSnapshotAsync(token)).Delivered);
        Assert.True((await store.VerifyLedgerAsync(token)).Intact);
        Assert.Equal(0, clock.ActiveTimers);
    }

    [Fact]
    public async Task Shutdown_DoesNotConvertCancellationToFailureOrStealLiveLease()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManualTimeProvider clock = new(TestEvents.Now);
        SqliteEventStore store = await OpenAsync(directory, clock, token);
        await EnqueueAsync(store, clock, "shutdown", token);
        AsyncOutput output = new(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable");
        });
        using CancellationTokenSource shutdown = CancellationTokenSource.CreateLinkedTokenSource(token);
        using QueueDeliveryWorker original = Worker(store, output, clock);
        Task<int> delivery = original.DeliverOnceAsync(shutdown.Token);
        await output.Started.Task.WaitAsync(TimeSpan.FromSeconds(10), token);

        SqliteEventStore reopened = await OpenAsync(directory, clock, token);
        using QueueDeliveryWorker restarted = Worker(reopened, AcknowledgeAll(), clock);
        Assert.Equal(0, await restarted.DeliverOnceAsync(token));
        await shutdown.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => delivery);
        QueueSnapshot snapshot = await reopened.GetSnapshotAsync(token);
        Assert.Equal((1L, 0L, 0L), (snapshot.Uploading, snapshot.Retrying, snapshot.DeadLettered));
        clock.Advance(TimeSpan.FromSeconds(89));
        Assert.Equal(0, await restarted.DeliverOnceAsync(token));
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(1, await restarted.DeliverOnceAsync(token));
        Assert.Equal(1, (await reopened.GetSnapshotAsync(token)).Delivered);
        Assert.True((await reopened.VerifyLedgerAsync(token)).Intact);
    }

    [Fact]
    public async Task CompletedOutput_SettlesAcknowledgementBeforeDeadline()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManualTimeProvider clock = new(TestEvents.Now);
        SqliteEventStore store = await OpenAsync(directory, clock, token);
        await EnqueueAsync(store, clock, "slow-success", token);
        AsyncOutput output = new((events, cancellationToken) =>
        {
            clock.Advance(TimeSpan.FromSeconds(59));
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Acknowledgement(events));
        });
        using QueueDeliveryWorker worker = Worker(store, output, clock);
        Assert.Equal(1, await worker.DeliverOnceAsync(token));
        Assert.Equal(1, (await store.GetSnapshotAsync(token)).Delivered);
        Assert.Equal(0, clock.ActiveTimers);
    }

    [Theory]
    [InlineData(30, 1)]
    [InlineData(3601, 60)]
    [InlineData(90, 0)]
    [InlineData(90, 61)]
    [InlineData(90, -1)]
    public void Settings_RejectUnsafeDeadlineAndLease(int lease, int timeout)
    {
        Assert.Throws<InvalidOperationException>(() => Settings(lease, timeout));
    }

    [Fact]
    public void Settings_BindDeliveryProfileAndIncludeItInConfigurationIdentity()
    {
        CollectorSettings settings = Settings(90, 60);
        Assert.Equal(TimeSpan.FromSeconds(90), settings.DeliveryOptions().LeaseDuration);
        Assert.Equal(TimeSpan.FromSeconds(60), settings.DeliveryOptions().DeliveryTimeout);
        Assert.NotEqual(settings.ConfigurationHash(), Settings(91, 60).ConfigurationHash());
        Assert.NotEqual(settings.ConfigurationHash(), Settings(90, 59).ConfigurationHash());
        CollectorSettings defaults = CollectorSettings.FromEnvironment(_ => null);
        Assert.Equal(TimeSpan.FromMinutes(5), defaults.DeliveryOptions().LeaseDuration);
        Assert.Equal(TimeSpan.FromMinutes(4), defaults.DeliveryOptions().DeliveryTimeout);
    }

    private static CollectorSettings Settings(int lease, int timeout) =>
        CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_DELIVERY_LEASE_SECONDS" => lease.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "BOWER_DELIVERY_TIMEOUT_SECONDS" => timeout.ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => null
        });

    private static async Task<SqliteEventStore> OpenAsync(TemporaryDirectory directory, TimeProvider clock, CancellationToken token)
    {
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(token);
        return store;
    }

    private static Task<EnqueueResult> EnqueueAsync(SqliteEventStore store, TimeProvider clock, string id, CancellationToken token) =>
        store.EnqueueAsync(new QueuedEvent(id, $"sha256:{id}", $$"""{"eventId":"{{id}}"}""", clock.GetUtcNow()), token);

    private static QueueDeliveryWorker Worker(IDurableEventStore store, IOutputAdapter output, TimeProvider clock) =>
        new(store, output, clock, new QueueDeliveryOptions
        {
            LeaseDuration = TimeSpan.FromSeconds(90),
            DeliveryTimeout = TimeSpan.FromSeconds(60),
            MaximumDeliveryAttempts = 1
        }, NullLogger<QueueDeliveryWorker>.Instance);

    private static DeliveryResult Acknowledgement(IReadOnlyList<QueuedEvent> events) =>
        new(events.Select(item => item.EventId).ToArray(), [], "test-destination");

    private static AsyncOutput AcknowledgeAll() => new((events, _) => Task.FromResult(Acknowledgement(events)));

    private sealed class AsyncOutput(Func<IReadOnlyList<QueuedEvent>, CancellationToken, Task<DeliveryResult>> deliver) : IOutputAdapter
    {
        public string Id => "test-deadline";
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
        {
            Task<DeliveryResult> delivery = deliver(events, cancellationToken);
            Started.TrySetResult();
            return delivery;
        }
    }
}
