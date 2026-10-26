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
    public void Intake_StartsEmptyForTheProcessLifetime()
    {
        FakeClock clock = new(TestEvents.Now);
        IntakeMetricsSnapshot snapshot = new PipelineTelemetry(clock).IntakeSnapshot();

        Assert.Equal(new IntakeMetricsSnapshot(TestEvents.Now, 0, 0, 0, 0, null, null), snapshot);
    }

    [Fact]
    public async Task Intake_ConcurrentUpdatesLoseNothing()
    {
        FakeClock clock = new(TestEvents.Now);
        PipelineTelemetry telemetry = new(clock);
        const int workers = 8;
        const int perWorker = 5_000;

        await Task.WhenAll(Enumerable.Range(0, workers).Select(_ => Task.Run(() =>
        {
            for (int index = 0; index < perWorker; index++)
            {
                telemetry.RecordAttempt(3);
                if (index % 2 == 0)
                {
                    telemetry.RecordCapacityRefusal(3);
                }
            }
        }, TestContext.Current.CancellationToken)));

        IntakeMetricsSnapshot snapshot = telemetry.IntakeSnapshot();
        Assert.Equal(workers * perWorker, snapshot.AttemptedRequests);
        Assert.Equal(workers * perWorker * 3L, snapshot.AttemptedBytes);
        Assert.Equal(workers * perWorker / 2, snapshot.CapacityRefusals);
        Assert.Equal(workers * perWorker / 2 * 3L, snapshot.CapacityRefusedBytes);
        Assert.Equal(TestEvents.Now, snapshot.LastRefusalAt);
    }
}
