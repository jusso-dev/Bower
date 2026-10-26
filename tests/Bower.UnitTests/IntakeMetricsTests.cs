using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class IntakeMetricsTests
{
    private static readonly CollectorIdentity Identity =
        new("collector-1", "0.1.0", "test", "sha256:configuration");

    [Fact]
    public async Task Process_FullQueueCountsEachAttemptAsRefusalAndRetryCountsIndependently()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(
            new QueuedEvent("filler", "sha256:filler", new string('x', 1_048_000), clock.UtcNow),
            cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock,
            telemetry);
        string candidate = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options);
        long bytes = Encoding.UTF8.GetByteCount(candidate);

        const int attempts = 3;
        for (int index = 0; index < attempts; index++)
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            await Assert.ThrowsAsync<QueueCapacityExceededException>(
                () => processor.ProcessAsync(candidate, Identity, cancellationToken));
        }

        IntakeMetricsSnapshot refused = telemetry.IntakeSnapshot();
        Assert.Equal(TestEvents.Now, refused.ObservedSince);
        Assert.Equal(attempts, refused.AttemptedRequests);
        Assert.Equal(attempts * bytes, refused.AttemptedBytes);
        Assert.Equal(attempts, refused.CapacityRefusals);
        Assert.Equal(attempts * bytes, refused.CapacityRefusedBytes);
        Assert.Equal(clock.UtcNow, refused.LastRefusalAt);
        Assert.Equal(PipelineTelemetry.QueueCapacityReason, refused.LastRefusalReason);
        // Refusals are not selection decisions and never count as committed events.
        PipelineMetricsSnapshot pipeline = telemetry.Snapshot();
        Assert.Equal(0, pipeline.EventsIn);
        Assert.Equal(0, pipeline.EventsQueued);
        Assert.Empty(pipeline.Rows);
        Assert.Equal(1, (await store.GetSnapshotAsync(cancellationToken)).Queued);
        Assert.Empty(telemetry.Sources());

        QueuedEvent filler = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken));
        await store.MarkDeliveredAsync(filler.EventId, "test-ack", filler.LeaseToken, cancellationToken);
        DateTimeOffset lastRefusal = clock.UtcNow;
        clock.Advance(TimeSpan.FromSeconds(1));
        ProcessingResult retried = await processor.ProcessAsync(candidate, Identity, cancellationToken);
        ProcessingResult repeated = await processor.ProcessAsync(candidate, Identity, cancellationToken);

        Assert.True(retried.Queued);
        Assert.False(retried.Duplicate);
        Assert.False(repeated.Queued);
        Assert.True(repeated.Duplicate);
        IntakeMetricsSnapshot after = telemetry.IntakeSnapshot();
        Assert.Equal(attempts + 2, after.AttemptedRequests);
        Assert.Equal((attempts + 2) * bytes, after.AttemptedBytes);
        Assert.Equal(attempts, after.CapacityRefusals);
        Assert.Equal(attempts * bytes, after.CapacityRefusedBytes);
        Assert.Equal(lastRefusal, after.LastRefusalAt);
        pipeline = telemetry.Snapshot();
        Assert.Equal(2, pipeline.EventsIn);
        Assert.Equal(1, pipeline.EventsQueued);
        Assert.Equal(1, pipeline.Duplicates);
        Assert.Equal(2 * bytes, pipeline.BytesIn);
    }

    [Fact]
    public async Task Process_AlertRefusedAfterCommitRecordsTheEventAndADistinctReason()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string candidate = TfnCandidate(clock);
        long bytes = Encoding.UTF8.GetByteCount(candidate);

        // Size the queue so the event fits and its privacy alert does not.
        RequestEventBuffer sizing = new();
        await PrivacyProcessor(sizing, clock, null).ProcessAsync(candidate, Identity, cancellationToken);
        Assert.Equal(2, sizing.Events.Count);
        int eventBytes = Encoding.UTF8.GetByteCount(sizing.Events[0].Payload);
        int alertBytes = Encoding.UTF8.GetByteCount(sizing.Events[1].Payload);
        SqliteEventStore store = await FilledStoreAsync(
            directory, clock, 1_048_576 - eventBytes - alertBytes + 1, cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = PrivacyProcessor(store, clock, telemetry);

        // Status code unchanged: the alert refusal still surfaces as backpressure (503).
        await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => processor.ProcessAsync(candidate, Identity, cancellationToken));

        Assert.Equal(2, (await store.GetSnapshotAsync(cancellationToken)).Queued);
        IntakeMetricsSnapshot intake = telemetry.IntakeSnapshot();
        Assert.Equal(1, intake.AttemptedRequests);
        Assert.Equal(0, intake.CapacityRefusals);
        Assert.Equal(0, intake.CapacityRefusedBytes);
        Assert.Equal(1, intake.PrivacyAlertRefusals);
        Assert.Equal(bytes, intake.PrivacyAlertRefusedBytes);
        Assert.Equal(PipelineTelemetry.PrivacyAlertCapacityReason, intake.LastRefusalReason);
        Assert.Equal(clock.UtcNow, intake.LastRefusalAt);
        PipelineMetricsSnapshot pipeline = telemetry.Snapshot();
        Assert.Equal(1, pipeline.EventsIn);
        Assert.Equal(1, pipeline.EventsQueued);
        Assert.Equal(eventBytes, pipeline.BytesQueued);
        SourceActivity source = Assert.Single(telemetry.Sources());
        Assert.Equal("TestApplication", source.Application);

        // The retry deduplicates the committed event and emits the alert.
        QueuedEvent filler = (await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken))
            .Single(item => item.EventId == "filler");
        await store.MarkDeliveredAsync(filler.EventId, "test-ack", filler.LeaseToken, cancellationToken);
        ProcessingResult retried = await processor.ProcessAsync(candidate, Identity, cancellationToken);
        Assert.True(retried.Duplicate);
        Assert.NotNull(retried.PrivacyAlertEventId);
        Assert.Equal(1, telemetry.Snapshot().EventsQueued);
        Assert.Equal(1, telemetry.Snapshot().Duplicates);
        Assert.Equal(1, telemetry.IntakeSnapshot().PrivacyAlertRefusals);
    }

    [Fact]
    public async Task Process_AlertRefusedForInvalidOrRejectedEventKeepsTheirSelectionOutcome()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await FilledStoreAsync(directory, clock, 1_048_000, cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = PrivacyProcessor(store, clock, telemetry);
        string invalid = TfnCandidate(clock, envelope => envelope with { SchemaVersion = "9.9.9" });
        string rejected = TfnCandidate(clock, envelope => envelope with { EventType = "unmatched_event" });

        await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => processor.ProcessAsync(invalid, Identity, cancellationToken));
        await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => processor.ProcessAsync(rejected, Identity, cancellationToken));

        IntakeMetricsSnapshot intake = telemetry.IntakeSnapshot();
        Assert.Equal(2, intake.AttemptedRequests);
        Assert.Equal(0, intake.CapacityRefusals);
        Assert.Equal(2, intake.PrivacyAlertRefusals);
        PipelineMetricsSnapshot pipeline = telemetry.Snapshot();
        Assert.Equal(2, pipeline.EventsIn);
        Assert.Equal(0, pipeline.EventsQueued);
        Assert.Equal(
            [("policy", "reject"), ("validation", "quarantine")],
            pipeline.Rows.Select(row => (row.Stage, row.Action)));
        Assert.Empty(telemetry.Sources());
        Assert.Equal(1, (await store.GetSnapshotAsync(cancellationToken)).Queued);
    }

    [Fact]
    public void Intake_StartsEmptyForTheProcessLifetime()
    {
        FakeClock clock = new(TestEvents.Now);
        IntakeMetricsSnapshot snapshot = new PipelineTelemetry(clock).IntakeSnapshot();

        Assert.Equal(new IntakeMetricsSnapshot(TestEvents.Now, 0, 0, 0, 0, 0, 0, null, null), snapshot);
    }

    [Fact]
    public void Intake_LastRefusalMovesForwardOnlyAndKeepsItsReason()
    {
        FakeClock clock = new(TestEvents.Now);
        PipelineTelemetry telemetry = new(clock);
        clock.Advance(TimeSpan.FromSeconds(2));
        telemetry.RecordPrivacyAlertRefusal(1);
        clock.Advance(TimeSpan.FromSeconds(-1));
        telemetry.RecordCapacityRefusal(1);

        IntakeMetricsSnapshot snapshot = telemetry.IntakeSnapshot();
        Assert.Equal(TestEvents.Now.AddSeconds(2), snapshot.LastRefusalAt);
        Assert.Equal(PipelineTelemetry.PrivacyAlertCapacityReason, snapshot.LastRefusalReason);
    }

    [Fact]
    public async Task Intake_ConcurrentUpdatesLoseNothingAndNeverTear()
    {
        FakeClock clock = new(TestEvents.Now);
        PipelineTelemetry telemetry = new(clock);
        const int workers = 8;
        const int perWorker = 5_000;
        using CancellationTokenSource done = new();
        int torn = 0;

        Task reader = Task.Run(() =>
        {
            while (!done.IsCancellationRequested)
            {
                IntakeMetricsSnapshot seen = telemetry.IntakeSnapshot();
                if ((seen.CapacityRefusals + seen.PrivacyAlertRefusals > 0 && seen.LastRefusalAt is null)
                    || seen.CapacityRefusals + seen.PrivacyAlertRefusals > seen.AttemptedRequests)
                {
                    Interlocked.Increment(ref torn);
                }
            }
        }, TestContext.Current.CancellationToken);
        await Task.WhenAll(Enumerable.Range(0, workers).Select(_ => Task.Run(() =>
        {
            for (int index = 0; index < perWorker; index++)
            {
                telemetry.RecordAttempt(3);
                if (index % 2 == 0)
                {
                    telemetry.RecordCapacityRefusal(3);
                }
                else if (index % 5 == 0)
                {
                    telemetry.RecordPrivacyAlertRefusal(3);
                }
            }
        }, TestContext.Current.CancellationToken)));
        await done.CancelAsync();
        await reader;

        IntakeMetricsSnapshot snapshot = telemetry.IntakeSnapshot();
        Assert.Equal(0, torn);
        Assert.Equal(workers * perWorker, snapshot.AttemptedRequests);
        Assert.Equal(workers * perWorker * 3L, snapshot.AttemptedBytes);
        Assert.Equal(workers * perWorker / 2, snapshot.CapacityRefusals);
        Assert.Equal(workers * perWorker / 2 * 3L, snapshot.CapacityRefusedBytes);
        Assert.Equal(workers * (perWorker / 10), snapshot.PrivacyAlertRefusals);
        Assert.Equal(workers * (perWorker / 10) * 3L, snapshot.PrivacyAlertRefusedBytes);
        Assert.Equal(TestEvents.Now, snapshot.LastRefusalAt);
    }

    private static SecurityEventProcessor PrivacyProcessor(
        IDurableEventStore store,
        FakeClock clock,
        PipelineTelemetry? telemetry) =>
        new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy(), TestEvents.PrivacyDetectionPolicy()]),
            store,
            clock,
            telemetry);

    private static string TfnCandidate(
        FakeClock clock,
        Func<SecurityEventEnvelope, SecurityEventEnvelope>? adjust = null)
    {
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["note"] = JsonSerializer.SerializeToElement("TFN 100000001")
            }
        };
        return JsonSerializer.Serialize(adjust?.Invoke(envelope) ?? envelope, BowerJson.Options);
    }

    private static async Task<SqliteEventStore> FilledStoreAsync(
        TemporaryDirectory directory,
        FakeClock clock,
        int fillerBytes,
        CancellationToken cancellationToken)
    {
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(
            new QueuedEvent("filler", "sha256:filler", new string('x', fillerBytes), clock.UtcNow),
            cancellationToken);
        return store;
    }
}
