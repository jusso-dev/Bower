using Bower.Abstractions;
using Bower.Collector;
using Bower.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
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

    [Fact]
    public async Task DeliveryActivity_RecordsTheLastFailureCodeAndLaterSuccess()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a"], cancellationToken);
        bool repaired = false;
        FakeOutput output = new(events => repaired
            ? new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "accepted")
            : new DeliveryResult([], [.. events.Select(item =>
                new DeliveryFailure(item.EventId, "destination-azure-credential-failed", true, null))], null));
        DeliveryActivity activity = new();
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions(), new RecordingLogger(), activity);

        await worker.DeliverOnceAsync(cancellationToken);

        Assert.Equal(new DeliveryFailureActivity("destination-azure-credential-failed", clock.UtcNow), activity.LastFailure);
        Assert.Null(activity.LastSuccessfulDeliveryAt);
        repaired = true;
        clock.Advance(TimeSpan.FromSeconds(31));
        await worker.DeliverOnceAsync(cancellationToken);
        Assert.Equal(clock.UtcNow, activity.LastSuccessfulDeliveryAt);
        // The failure stays as history; consumers compare it with the last success.
        Assert.Equal("destination-azure-credential-failed", activity.LastFailure?.Code);
    }

    [Fact]
    public async Task DeliveryActivity_ReportsAnUnavailableLocalSyslogDaemonByName()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a"], cancellationToken);
        FakeOutput output = new(events => new DeliveryResult([], [.. events.Select(item =>
            new DeliveryFailure(item.EventId, Bower.Output.AmaSyslog.AmaSyslogOutput.SocketUnavailableCode, true, null))], null));
        DeliveryActivity activity = new();
        RecordingLogger logger = new();
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions(), logger, activity);

        await worker.DeliverOnceAsync(cancellationToken);

        // Persisted, logged and shown in /v1/status under its own name, not "delivery-failure".
        Assert.Equal("destination-ama-syslog-unavailable", activity.LastFailure?.Code);
        Assert.Contains(logger.Messages, line => line.Contains("destination-ama-syslog-unavailable", StringComparison.Ordinal));
        Assert.Equal(1, (await store.GetSnapshotAsync(cancellationToken)).Retrying);
    }

    [Theory]
    [InlineData("destination-ama-syslog-busy")]
    [InlineData("destination-ama-syslog-access-denied")]
    [InlineData("destination-ama-syslog-cancelled")]
    public async Task DeliveryActivity_ReportsEachAmaSyslogOutputFailureByName(string code)
    {
        // #225, #227, #229: every code the adapter returns is on both allow-lists, so status,
        // logs and the queue show it instead of "destination-output-failure".
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a"], cancellationToken);
        FakeOutput output = new(events => new DeliveryResult([], [.. events.Select(item => new DeliveryFailure(item.EventId, code, true, null))], null));
        DeliveryActivity activity = new();
        RecordingLogger logger = new();
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions(), logger, activity);

        await worker.DeliverOnceAsync(cancellationToken);

        Assert.Equal(code, activity.LastFailure?.Code);
        Assert.Contains(logger.Messages, line => line.Contains(code, StringComparison.Ordinal));
        Assert.Equal(1, (await store.GetSnapshotAsync(cancellationToken)).Retrying);
    }

    [Fact]
    public void DestinationRetryDelay_IsShorterForABusySyslogDaemonThanForAnOutage()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), QueueDeliveryWorker.DestinationRetryDelay("destination-ama-syslog-busy"));
        Assert.Equal(TimeSpan.FromSeconds(30), QueueDeliveryWorker.DestinationRetryDelay("destination-ama-syslog-unavailable"));
        Assert.Equal(TimeSpan.FromSeconds(30), QueueDeliveryWorker.DestinationRetryDelay("destination-azure-unavailable"));
    }

    [Fact]
    public async Task DeliveryTelemetry_DoesNotExposeUntrustedFailureCodesOrHideCredentialFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["credential", "untrusted"], cancellationToken);
        const string secret = "secret-marker-never-log";
        FakeOutput output = new(events => new DeliveryResult([], [.. events.Select(item =>
            new DeliveryFailure(item.EventId, item.EventId == "credential"
                ? "destination-azure-http-401:retry-after-capped" : $"relay-rejected:{secret}", true, null))], null));
        DeliveryActivity activity = new();
        RecordingLogger logger = new();
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions(), logger, activity);

        await worker.DeliverOnceAsync(cancellationToken);

        Assert.Equal("destination-azure-http-401", activity.LastFailure?.Code);
        Assert.DoesNotContain(logger.Messages, line => line.Contains(secret, StringComparison.Ordinal));
        Assert.Contains(logger.Messages, line => line.Contains("delivery-failure", StringComparison.Ordinal));
        Assert.Equal(2, (await store.GetSnapshotAsync(cancellationToken)).Retrying);
        await using SqliteConnection connection = new($"Data Source={Path.Combine(directory.Path, "queue.db")}");
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT last_failure_code FROM queue_events_v5 WHERE event_id = 'untrusted'";
        Assert.Equal("relay-rejected:unknown", await command.ExecuteScalarAsync(cancellationToken));
    }

    [Fact]
    public async Task UnknownDestinationFailure_StaysRetryableWithoutPersistingItsUntrustedCode()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, token);
        await EnqueueAsync(store, clock, ["event"], token);
        FakeOutput output = new(events => new DeliveryResult([], events.Select(item =>
            new DeliveryFailure(item.EventId, "destination-synthetic-secret-marker", true, null)).ToArray(), null));
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions { MaximumDeliveryAttempts = 1 }, NullLogger<QueueDeliveryWorker>.Instance);
        await worker.DeliverOnceAsync(token);
        clock.Advance(TimeSpan.FromSeconds(31));
        await worker.DeliverOnceAsync(token);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(token);
        Assert.Equal(1, snapshot.Retrying);
        Assert.Equal(0, snapshot.DeadLettered);
        await using SqliteConnection connection = new($"Data Source={Path.Combine(directory.Path, "queue.db")}");
        await connection.OpenAsync(token);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT last_failure_code FROM queue_events_v5 WHERE event_id = 'event'";
        Assert.Equal("destination-output-failure", await command.ExecuteScalarAsync(token));
    }

    [Fact]
    public async Task RelayRejection_StoresOnlyTheBoundedCodeInDeadLetterMetadata()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, token);
        await EnqueueAsync(store, clock, ["event"], token);
        FakeOutput output = new(events => new DeliveryResult([], events.Select(item =>
            new DeliveryFailure(item.EventId, "relay-rejected:synthetic-secret-marker", false, null)).ToArray(), null));
        await CreateWorker(store, output, clock).DeliverOnceAsync(token);
        DeadLetterRecord row = Assert.Single(await store.ListDeadLetteredAsync(10, token));
        Assert.Equal("relay-rejected:unknown", row.FailureCode);
        await using SqliteConnection connection = new($"Data Source={Path.Combine(directory.Path, "queue.db")}");
        await connection.OpenAsync(token);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT last_failure_code FROM queue_events_v5 WHERE event_id = 'event'";
        Assert.Equal("relay-rejected:unknown", await command.ExecuteScalarAsync(token));
    }

    [Fact]
    public async Task CredentialFailure_KeepsEventsQueuedAndLogsOnlyMetadata()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await EnqueueAsync(store, clock, ["a", "b", "poison"], cancellationToken);
        bool repaired = false;
        FakeOutput output = new(events => repaired
            ? new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "accepted")
            : new DeliveryResult([], events.Select(item => item.EventId == "poison"
                ? new DeliveryFailure(item.EventId, "payload-invalid-json", false, null)
                : new DeliveryFailure(item.EventId, "destination-azure-credential-failed", true, null)).ToArray(), null));
        RecordingLogger logger = new();
        QueueDeliveryWorker worker = new(store, output, clock,
            new QueueDeliveryOptions { MaximumDeliveryAttempts = 1 }, logger);

        await worker.DeliverOnceAsync(cancellationToken);

        Assert.Equal(
            [
                "Output adapter fake did not deliver 2 events (destination-azure-credential-failed); retrying.",
                "Output adapter fake did not deliver 1 events (payload-invalid-json); dead-lettered."
            ],
            logger.Messages);
        QueueSnapshot outage = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal(2, outage.Retrying);
        Assert.Equal(0, outage.Delivered);

        // A credential outage never spends the poison budget: after the fix it drains.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            clock.Advance(TimeSpan.FromSeconds(30));
            await worker.DeliverOnceAsync(cancellationToken);
        }

        Assert.Equal(2, (await store.GetSnapshotAsync(cancellationToken)).Retrying);
        repaired = true;
        clock.Advance(TimeSpan.FromSeconds(30));
        await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot recovered = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal(2, recovered.Delivered);
        Assert.Equal(1, recovered.DeadLettered);
    }

    [Fact]
    public async Task ExcessiveDestinationDeadline_IsCappedAndRecoversAfterRestart()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, token);
        await EnqueueAsync(store, clock, ["valid"], token);
        FakeOutput failing = new(events => new DeliveryResult([], events.Select(item =>
            new DeliveryFailure(item.EventId, "destination-azure-http-429", true, clock.UtcNow.AddYears(50))).ToArray(), null));
        await CreateWorker(store, failing, clock).DeliverOnceAsync(token);
        SqliteEventStore reopened = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await reopened.InitializeAsync(token);
        FakeOutput accepting = new(events => new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "accepted"));
        QueueDeliveryWorker worker = CreateWorker(reopened, accepting, clock);
        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.Equal(0, await worker.DeliverOnceAsync(token));
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, await worker.DeliverOnceAsync(token));
        Assert.Equal(1, (await reopened.GetSnapshotAsync(token)).Delivered);
    }

    [Fact]
    public async Task IsolatedRejectedRecord_DoesNotPauseHealthyBacklog()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore store, FakeClock clock) = await CreateStoreAsync(directory, token);
        await EnqueueAsync(store, clock, ["bad", "good"], token);
        FakeOutput output = new(events => new DeliveryResult(
            events.Where(item => item.EventId != "bad").Select(item => item.EventId).ToArray(),
            events.Where(item => item.EventId == "bad").Select(item =>
                new DeliveryFailure(item.EventId, "azure-http-400-isolated", false, null)).ToArray(), "accepted"));
        QueueDeliveryWorker worker = CreateWorker(store, output, clock);
        Assert.Equal(2, await worker.DeliverOnceAsync(token));
        await EnqueueAsync(store, clock, ["backlog"], token);
        Assert.Equal(1, await worker.DeliverOnceAsync(token));
        Assert.Equal(2, (await store.GetSnapshotAsync(token)).Delivered);
        Assert.Equal(1, (await store.GetSnapshotAsync(token)).DeadLettered);
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

    [Fact]
    public async Task BusyQueue_IsAQuietBackOff_UntilItLastsBusyWarningAfter_ThenAWarning()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, _) = await CreateStoreAsync(directory, cancellationToken);
        FlakyStore store = new(inner, int.MaxValue, busy: true);
        BusyLogProbe logger = new();
        StepTimestampClock clock = new();
        QueueDeliveryWorker worker = new(store, new FakeOutput(_ => throw new InvalidOperationException("not reached")),
            clock, new QueueDeliveryOptions { BusyDelay = TimeSpan.Zero, BusyWarningAfter = TimeSpan.FromMilliseconds(300) },
            logger);

        await worker.StartAsync(cancellationToken);
        try
        {
            await logger.FirstBusy.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            Assert.DoesNotContain(LogLevel.Warning, logger.BusyLevels);
            clock.Advance(TimeSpan.FromSeconds(1));
            await logger.BusyWarning.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        }
        finally
        {
            await worker.StopAsync(cancellationToken);
        }

        Assert.Contains(LogLevel.Warning, logger.BusyLevels);
        Assert.DoesNotContain(1002, logger.EventIds);
    }

    [Fact]
    public async Task AlternatingFailures_DoNotDefeatLogRateLimits()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, _) = await CreateStoreAsync(directory, cancellationToken);
        TaskCompletionSource lastAttempt = new(TaskCreationOptions.RunContinuationsAsynchronously);
        FlakyStore store = new(inner, 24, failureFactory: attempt =>
        {
            if (attempt == 24) lastAttempt.TrySetResult();
            return attempt % 2 == 0
                ? new InvalidOperationException("other storage failure")
                : new SqliteException("database is locked", 5);
        });
        BusyLogProbe logger = new();
        QueueDeliveryWorker worker = new(store, new FakeOutput(_ => throw new InvalidOperationException("not reached")),
            new StepTimestampClock(), new QueueDeliveryOptions
            {
                BusyDelay = TimeSpan.Zero,
                ErrorDelay = TimeSpan.Zero,
                BusyWarningAfter = TimeSpan.FromMinutes(1)
            }, logger);
        await worker.StartAsync(cancellationToken);
        try
        {
            await lastAttempt.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        }
        finally
        {
            await worker.StopAsync(cancellationToken);
        }
        Assert.InRange(logger.EventIds.Count(id => id == 1002), 1, 2);
        Assert.InRange(logger.EventIds.Count(id => id == 1009), 1, 2);
    }

    [Fact]
    public async Task SustainedBusyAfterOtherFailure_WarnsAgainAtPeriodicLog()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, _) = await CreateStoreAsync(directory, cancellationToken);
        StepTimestampClock clock = new();
        FlakyStore store = new(inner, 13, failureFactory: attempt =>
        {
            if (attempt is 2 or 5) clock.Advance(TimeSpan.FromSeconds(1));
            return attempt == 3
                ? new InvalidOperationException("other storage failure")
                : new SqliteException("database is locked", 5);
        });
        BusyLogProbe logger = new();
        QueueDeliveryWorker worker = new(store, new FakeOutput(_ => throw new InvalidOperationException("not reached")),
            clock, new QueueDeliveryOptions
            {
                BusyDelay = TimeSpan.Zero,
                ErrorDelay = TimeSpan.Zero,
                BusyWarningAfter = TimeSpan.FromMilliseconds(100)
            }, logger);
        await worker.StartAsync(cancellationToken);
        try
        {
            await logger.ThirdBusy.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        }
        finally
        {
            await worker.StopAsync(cancellationToken);
        }
        Assert.Equal([LogLevel.Information, LogLevel.Warning, LogLevel.Warning], logger.BusyLevels.ToArray());
    }

    [Fact]
    public async Task DifferentFailure_InterruptsTheConsecutiveBusyInterval()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, _) = await CreateStoreAsync(directory, cancellationToken);
        StepTimestampClock clock = new();
        FlakyStore store = new(inner, 13, failureFactory: attempt =>
        {
            if (attempt == 2)
            {
                clock.Advance(TimeSpan.FromSeconds(1));
                return new InvalidOperationException("other storage failure");
            }

            return new SqliteException("database is locked", 5);
        });
        BusyLogProbe logger = new();
        QueueDeliveryWorker worker = new(store, new FakeOutput(_ => throw new InvalidOperationException("not reached")),
            clock, new QueueDeliveryOptions
            {
                BusyDelay = TimeSpan.Zero,
                ErrorDelay = TimeSpan.Zero,
                BusyWarningAfter = TimeSpan.FromMilliseconds(100)
            }, logger);

        await worker.StartAsync(cancellationToken);
        try
        {
            await logger.SecondBusy.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        }
        finally
        {
            await worker.StopAsync(cancellationToken);
        }

        Assert.Equal([LogLevel.Information, LogLevel.Information], logger.BusyLevels.ToArray());
    }

    [Fact]
    public async Task BusySettlement_IsRetried_SoTheBatchIsNotLeftLeased()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await inner.EnqueueAsync(new QueuedEvent("busy-1", "sha256:busy-1", """{"eventId":"busy-1"}""", clock.UtcNow), cancellationToken);
        FlakyStore store = new(inner, 0, failedBatchFailures: 2, busy: true);
        QueueDeliveryWorker worker = new(store,
            new FakeOutput(events => new DeliveryResult([], [.. events.Select(item => new DeliveryFailure(item.EventId, "output-adapter-failure", true, null))], null)),
            clock, new QueueDeliveryOptions { BusyDelay = TimeSpan.Zero }, new RecordingLogger());

        Assert.Equal(1, await worker.DeliverOnceAsync(cancellationToken));
        Assert.Equal(3, store.FailedBatchCalls);
        QueueSnapshot snapshot = await inner.GetSnapshotAsync(cancellationToken);
        Assert.Equal((1L, 0L), (snapshot.Retrying, snapshot.Uploading));
    }

    [Theory]
    [InlineData(2, false)]
    [InlineData(5, true)]
    public async Task BusyAcknowledgementSettlement_RetriesOrReplaysAfterLeaseExpiry(int busyFailures, bool exhausted)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (SqliteEventStore inner, FakeClock clock) = await CreateStoreAsync(directory, cancellationToken);
        await inner.EnqueueAsync(new QueuedEvent("ack-busy", "sha256:ack-busy", """{"eventId":"ack-busy"}""", clock.UtcNow), cancellationToken);
        FlakyStore store = new(inner, 0, busy: true, deliveredBatchFailures: busyFailures);
        int uploads = 0;
        QueueDeliveryWorker worker = new(store, new FakeOutput(events =>
        {
            uploads++;
            return new DeliveryResult(events.Select(item => item.EventId).ToArray(), [], "accepted");
        }), clock, new QueueDeliveryOptions { BusyDelay = TimeSpan.Zero, SettlementAttempts = 5 }, new RecordingLogger());

        if (exhausted)
        {
            await Assert.ThrowsAsync<SqliteException>(() => worker.DeliverOnceAsync(cancellationToken));
            Assert.Equal(5, store.DeliveredBatchCalls);
            Assert.Equal(1, (await inner.GetSnapshotAsync(cancellationToken)).Uploading);
            // The destination has already accepted the event. The expired lease makes the
            // next upload a replay; a destination must deduplicate it by event identity.
            clock.Advance(TimeSpan.FromHours(1));
        }
        Assert.Equal(1, await worker.DeliverOnceAsync(cancellationToken));
        Assert.Equal(exhausted ? 2 : 1, uploads);
        Assert.Equal(exhausted ? 6 : 3, store.DeliveredBatchCalls);
        Assert.Equal(1, (await inner.GetSnapshotAsync(cancellationToken)).Delivered);
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
        int failedBatchFailures = 0,
        bool busy = false,
        Func<int, Exception>? failureFactory = null,
        int deliveredBatchFailures = 0) : IDurableEventStore
    {
        private Exception Failure() => busy
            ? new Microsoft.Data.Sqlite.SqliteException("database is locked", 5)
            : new InvalidOperationException("database is locked");

        public int Failures { get; private set; }

        public int FailedBatchCalls { get; private set; }

        public int DeliveredBatchCalls { get; private set; }

        public Task<IReadOnlyList<string>> MarkFailedBatchAsync(
            IReadOnlyList<FailureSettlement> failures,
            CancellationToken cancellationToken = default)
        {
            FailedBatchCalls++;
            if (FailedBatchCalls <= failedBatchFailures)
            {
                throw Failure();
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
                throw failureFactory?.Invoke(Failures) ?? Failure();
            }

            return inner.LeaseAsync(maximumCount, leaseDuration, cancellationToken);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) =>
            inner.InitializeAsync(cancellationToken);

        public Task<EnqueueResult> EnqueueAsync(QueuedEvent candidate, CancellationToken cancellationToken = default) =>
            inner.EnqueueAsync(candidate, cancellationToken);

        public Task MarkDeliveredAsync(string eventId, string acknowledgement, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkDeliveredAsync(eventId, acknowledgement, leaseToken, cancellationToken);

        public Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(IReadOnlyList<string> eventIds, string acknowledgement, IReadOnlyDictionary<string, string>? leaseTokens, CancellationToken cancellationToken = default)
        {
            DeliveredBatchCalls++;
            if (DeliveredBatchCalls <= deliveredBatchFailures)
            {
                throw Failure();
            }
            return inner.MarkDeliveredBatchAsync(eventIds, acknowledgement, leaseTokens, cancellationToken);
        }

        public Task MarkRetryingAsync(string eventId, string failureCode, DateTimeOffset retryAfter, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkRetryingAsync(eventId, failureCode, retryAfter, leaseToken, cancellationToken);

        public Task MarkDeadLetteredAsync(string eventId, string failureCode, string? leaseToken, CancellationToken cancellationToken = default) =>
            inner.MarkDeadLetteredAsync(eventId, failureCode, leaseToken, cancellationToken);

        public Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
            inner.GetSnapshotAsync(cancellationToken);

        public Task<int> PurgeDeliveredAsync(DateTimeOffset deliveredBefore, int maximumCount, CancellationToken cancellationToken = default) =>
            inner.PurgeDeliveredAsync(deliveredBefore, maximumCount, cancellationToken);

        public Task<int> PurgeDeliveredAsync(DateTimeOffset deliveredBefore, int maximumCount, long archivedThroughSequence,
            CancellationToken cancellationToken = default) =>
            inner.PurgeDeliveredAsync(deliveredBefore, maximumCount, archivedThroughSequence, cancellationToken);

        public Task<int> CloseExpiredSuppressionWindowsAsync(DateTimeOffset now, Func<SuppressionWindow, QueuedEvent> createSummary,
            CancellationToken cancellationToken = default) =>
            inner.CloseExpiredSuppressionWindowsAsync(now, createSummary, cancellationToken);

        public Task<IReadOnlyList<SourceActivity>> GetSourceActivityAsync(CancellationToken cancellationToken = default) =>
            inner.GetSourceActivityAsync(cancellationToken);

        public Task UpsertSourceActivityAsync(IReadOnlyCollection<SourceActivity> activity, CancellationToken cancellationToken = default) =>
            inner.UpsertSourceActivityAsync(activity, cancellationToken);

        public Task<IReadOnlyList<SourceMonitoring>> GetSourceMonitoringAsync(CancellationToken cancellationToken = default) =>
            inner.GetSourceMonitoringAsync(cancellationToken);

        public Task<IReadOnlyList<SourceMonitoring>> StartSourceMonitoringAsync(IReadOnlyCollection<SourceMonitoring> expected, CancellationToken cancellationToken = default) =>
            inner.StartSourceMonitoringAsync(expected, cancellationToken);

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

    private sealed class StepTimestampClock : TimeProvider
    {
        private long ticks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Read(ref ticks);

        public void Advance(TimeSpan amount) => Interlocked.Add(ref ticks, amount.Ticks);
    }

    private sealed class BusyLogProbe : ILogger<QueueDeliveryWorker>
    {
        public System.Collections.Concurrent.ConcurrentQueue<LogLevel> BusyLevels { get; } = new();
        public System.Collections.Concurrent.ConcurrentQueue<int> EventIds { get; } = new();

        public TaskCompletionSource FirstBusy { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SecondBusy { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ThirdBusy { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource BusyWarning { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            EventIds.Enqueue(eventId.Id);
            if (eventId.Id == 1009)
            {
                BusyLevels.Enqueue(logLevel);
                FirstBusy.TrySetResult();
                if (logLevel == LogLevel.Warning) BusyWarning.TrySetResult();
                if (BusyLevels.Count == 2)
                {
                    SecondBusy.TrySetResult();
                }
                if (BusyLevels.Count == 3)
                {
                    ThirdBusy.TrySetResult();
                }
            }
        }
    }

    private sealed class RecordingLogger : ILogger<QueueDeliveryWorker>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Messages.Add(formatter(state, exception));
            }
        }
    }
}
