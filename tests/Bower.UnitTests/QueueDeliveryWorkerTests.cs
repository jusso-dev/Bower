using Bower.Abstractions;
using Bower.Collector;
using Bower.Persistence;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class QueueDeliveryWorkerTests
{
    [Fact]
    public async Task DeliverOnce_SettlesAcknowledgedRetryableAndPermanentFailures()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["ok", "retry", "bad"], cancellationToken);
        FakeOutput output = new(_ => new DeliveryResult(
            ["ok"],
            [
                new DeliveryFailure("retry", "azure-http-503", true, null),
                new DeliveryFailure("bad", "azure-http-400", false, null)
            ],
            "ack-1"));

        int leased = await CreateWorker(store, output, clock).DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(3, leased);
        Assert.Equal(1, snapshot.Delivered);
        Assert.Equal(1, snapshot.Retrying);
        Assert.Equal(1, snapshot.DeadLettered);
        Assert.Equal(0, snapshot.Uploading);
    }

    [Fact]
    public async Task DeliverOnce_RetriesWholeBatchWhenAdapterThrows()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a", "b"], cancellationToken);
        FakeOutput output = new(_ => throw new HttpRequestException("network down"));

        await CreateWorker(store, output, clock).DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(2, snapshot.Retrying);
        Assert.Equal(0, snapshot.Delivered);
    }

    [Fact]
    public async Task DeliverOnce_ToleratesDuplicateUnknownAndMissingResults()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a", "b", "c"], cancellationToken);
        // "a" is both acknowledged and failed, "ghost" was never leased, "c" is missing.
        FakeOutput output = new(_ => new DeliveryResult(
            ["a", "ghost", "b"],
            [new DeliveryFailure("a", "azure-http-500", true, null)],
            "ack"));

        await CreateWorker(store, output, clock).DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(2, snapshot.Delivered);
        Assert.Equal(1, snapshot.Retrying);
        Assert.Equal(0, snapshot.Uploading);
    }

    [Fact]
    public async Task DeliverOnce_DeadLettersAfterMaximumAttempts()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["poison"], cancellationToken);
        FakeOutput output = new(events => new DeliveryResult(
            [],
            events.Select(item => new DeliveryFailure(item.EventId, "azure-http-500", true, null)).ToArray(),
            null));
        QueueDeliveryWorker worker = CreateWorker(store, output, clock, maximumAttempts: 2);

        await worker.DeliverOnceAsync(cancellationToken);
        clock.Advance(TimeSpan.FromHours(1));
        await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(1, snapshot.DeadLettered);
        Assert.Equal(0, snapshot.Retrying);
    }

    [Fact]
    public async Task DeliverOnce_IgnoresSettlementOfReclaimedLease()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["slow"], cancellationToken);
        FakeOutput output = new(events =>
        {
            // Another worker reclaims and delivers the event while this delivery is slow.
            clock.Advance(TimeSpan.FromMinutes(10));
            IReadOnlyList<QueuedEvent> reclaimed = store
                .LeaseAsync(10, TimeSpan.FromMinutes(5), CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            store.MarkDeliveredAsync(reclaimed[0].EventId, "other-worker", reclaimed[0].LeaseToken, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            return new DeliveryResult(
                [],
                [new DeliveryFailure("slow", "timeout", true, null)],
                null);
        });

        await CreateWorker(store, output, clock).DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(1, snapshot.Delivered);
    }

    [Fact]
    public async Task DeliverOnce_BatchAcknowledgementSkipsOnlyTheReclaimedEvent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["slow", "fast"], cancellationToken);
        FakeOutput output = new(events =>
        {
            // Another worker reclaims "slow" and settles it before this batch acknowledges.
            clock.Advance(TimeSpan.FromMinutes(10));
            var reclaimed = store.LeaseAsync(1, TimeSpan.FromMinutes(5), CancellationToken.None).GetAwaiter().GetResult();
            store.MarkDeliveredAsync("slow", "other-worker", reclaimed[0].LeaseToken, CancellationToken.None).GetAwaiter().GetResult();
            return new DeliveryResult(["slow", "fast"], [], "ack-batch");
        });

        int leased = await CreateWorker(store, output, clock).DeliverOnceAsync(cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(2, leased);
        Assert.Equal(2, snapshot.Delivered);
        Assert.Equal(0, snapshot.Uploading);
        Assert.Equal(0, snapshot.Retrying);
    }

    [Fact]
    public async Task DeliverOnce_SettlesAllFailuresInOneBatchAllOrNothing()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["ok", "retry", "bad", "missing"], cancellationToken);
        FlakyStore flaky = new(store, failuresBeforeSuccess: 0, failedBatchFailures: 1);
        FakeOutput output = new(events => new DeliveryResult(
            events.Any(item => item.EventId == "ok") ? ["ok"] : [],
            events
                .Where(item => item.EventId is "retry" or "bad")
                .Select(item => new DeliveryFailure(item.EventId, item.EventId == "bad" ? "azure-http-400" : "azure-http-503", item.EventId == "retry", null))
                .ToArray(),
            "ack-1"));
        QueueDeliveryWorker worker = CreateWorker(flaky, output, clock);

        // The failure batch fails: acknowledged events stay delivered, every failed event stays
        // leased (none half-settled) and is redelivered once the lease expires.
        await Assert.ThrowsAsync<InvalidOperationException>(() => worker.DeliverOnceAsync(cancellationToken));
        QueueSnapshot afterFailure = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal((1L, 3L, 0L, 0L), (afterFailure.Delivered, afterFailure.Uploading, afterFailure.Retrying, afterFailure.DeadLettered));

        clock.Advance(TimeSpan.FromMinutes(6));
        int redelivered = await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot settled = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(3, redelivered);
        Assert.Equal(2, flaky.FailedBatchCalls);
        Assert.Equal(
            (1L, 0L, 2L, 1L),
            (settled.Delivered, settled.Uploading, settled.Retrying, settled.DeadLettered));
        Assert.True((await store.VerifyLedgerAsync(cancellationToken)).Intact);
    }

    [Fact]
    public async Task Worker_KeepsRunningAfterStorageFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a"], cancellationToken);
        FlakyStore flaky = new(store, failuresBeforeSuccess: 2);
        TaskCompletionSource delivered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        FakeOutput output = new(events =>
        {
            delivered.TrySetResult();
            return new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "ack");
        });
        using QueueDeliveryWorker worker = new(
            flaky,
            output,
            TimeProvider.System,
            new QueueDeliveryOptions
            {
                IdleDelay = TimeSpan.FromMilliseconds(10),
                ErrorDelay = TimeSpan.FromMilliseconds(10)
            },
            NullLogger<QueueDeliveryWorker>.Instance);

        await worker.StartAsync(cancellationToken);
        await delivered.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        await worker.StopAsync(cancellationToken);

        Assert.Equal(2, flaky.Failures);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(429)]
    [InlineData(503)]
    public async Task DestinationOutage_SurvivesRestartPreservesBudgetAndPausesNewBacklog(int status)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["valid"], cancellationToken);
        bool repaired = false;
        int calls = 0;
        FakeOutput output = new(events =>
        {
            calls++;
            Assert.All(events, item => Assert.Equal(1, item.DeliveryAttempts));
            return repaired ? new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "accepted")
                : new DeliveryResult([], events.Select(item => new DeliveryFailure(item.EventId,
                    $"destination-azure-http-{status}", true, clock.UtcNow.AddMinutes(2))).ToArray(), null);
        });
        // A poison budget of one must never dead-letter a destination outage.
        await CreateWorker(store, output, clock, maximumAttempts: 1).DeliverOnceAsync(cancellationToken);
        await EnqueueAsync(store, clock, ["new-backlog"], cancellationToken);
        SqliteEventStore reopened = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await reopened.InitializeAsync(cancellationToken);
        QueueDeliveryWorker restarted = CreateWorker(reopened, output, clock, maximumAttempts: 1);
        clock.Advance(TimeSpan.FromSeconds(119));
        Assert.Equal(0, await restarted.DeliverOnceAsync(cancellationToken));
        Assert.Equal(1, calls);
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(2, await restarted.DeliverOnceAsync(cancellationToken));
        Assert.Equal(0, (await reopened.GetSnapshotAsync(cancellationToken)).DeadLettered);
        repaired = true;
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(2, await restarted.DeliverOnceAsync(cancellationToken));
        Assert.Equal(2, (await reopened.GetSnapshotAsync(cancellationToken)).Delivered);
    }

    private static QueueDeliveryWorker CreateWorker(
        IDurableEventStore store,
        IOutputAdapter output,
        TimeProvider clock,
        int maximumAttempts = 20) =>
        new(
            store,
            output,
            clock,
            new QueueDeliveryOptions { MaximumDeliveryAttempts = maximumAttempts },
            NullLogger<QueueDeliveryWorker>.Instance);

    private static async Task<(SqliteEventStore Store, FakeClock Clock)> CreateStoreAsync(
        TemporaryDirectory directory,
        CancellationToken cancellationToken)
    {
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        return (store, clock);
    }

    private static async Task EnqueueAsync(
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

    private sealed class FakeOutput(Func<IReadOnlyList<QueuedEvent>, DeliveryResult> deliver) : IOutputAdapter
    {
        public string Id => "fake";

        public Task<DeliveryResult> DeliverAsync(
            IReadOnlyList<QueuedEvent> events,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(deliver(events));
    }

    private sealed class FlakyStore(
        IDurableEventStore inner,
        int failuresBeforeSuccess,
        int failedBatchFailures = 0) : IDurableEventStore
    {
        public int Failures { get; private set; }

        public int FailedBatchCalls { get; private set; }

        public Task<IReadOnlyList<string>> MarkFailedBatchAsync(
            IReadOnlyList<FailureSettlement> failures,
            CancellationToken cancellationToken = default)
        {
            FailedBatchCalls++;
            if (FailedBatchCalls <= failedBatchFailures)
            {
                throw new InvalidOperationException("database is locked");
            }

            return inner.MarkFailedBatchAsync(failures, cancellationToken);
        }

        public Task<IReadOnlyList<QueuedEvent>> LeaseAsync(
            int maximumCount,
            TimeSpan leaseDuration,
            CancellationToken cancellationToken = default)
        {
            if (Failures < failuresBeforeSuccess)
            {
                Failures++;
                throw new InvalidOperationException("database is locked");
            }

            return inner.LeaseAsync(maximumCount, leaseDuration, cancellationToken);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) =>
            inner.InitializeAsync(cancellationToken);

        public Task<EnqueueResult> EnqueueAsync(QueuedEvent candidate, CancellationToken cancellationToken = default) =>
            inner.EnqueueAsync(candidate, cancellationToken);

        public Task MarkDeliveredAsync(string eventId, string acknowledgement, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkDeliveredAsync(eventId, acknowledgement, leaseToken, cancellationToken);

        public Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(IReadOnlyList<string> eventIds, string acknowledgement, IReadOnlyDictionary<string, string>? leaseTokens, CancellationToken cancellationToken = default) =>
            inner.MarkDeliveredBatchAsync(eventIds, acknowledgement, leaseTokens, cancellationToken);

        public Task MarkRetryingAsync(string eventId, string failureCode, DateTimeOffset retryAfter, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkRetryingAsync(eventId, failureCode, retryAfter, leaseToken, cancellationToken);

        public Task MarkDeadLetteredAsync(string eventId, string failureCode, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkDeadLetteredAsync(eventId, failureCode, leaseToken, cancellationToken);

        public Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
            inner.GetSnapshotAsync(cancellationToken);

        public Task<int> PurgeDeliveredAsync(DateTimeOffset deliveredBefore, int maximumCount, CancellationToken cancellationToken = default) =>
            inner.PurgeDeliveredAsync(deliveredBefore, maximumCount, cancellationToken);

        public Task MaintainAsync(CancellationToken cancellationToken = default) =>
            inner.MaintainAsync(cancellationToken);

        public Task<IReadOnlyList<DeadLetterRecord>> ListDeadLetteredAsync(int maximumCount, CancellationToken cancellationToken = default) =>
            inner.ListDeadLetteredAsync(maximumCount, cancellationToken);

        public Task<int> ReplayDeadLetteredAsync(string? failureCodePrefix, IReadOnlyCollection<string>? eventIds, int maximumCount, CancellationToken cancellationToken = default) =>
            inner.ReplayDeadLetteredAsync(failureCodePrefix, eventIds, maximumCount, cancellationToken);

        public Task<LedgerHead> GetLedgerHeadAsync(CancellationToken cancellationToken = default) =>
            inner.GetLedgerHeadAsync(cancellationToken);

        public Task<LedgerVerification> VerifyLedgerAsync(CancellationToken cancellationToken = default) =>
            inner.VerifyLedgerAsync(cancellationToken);
    }
}
