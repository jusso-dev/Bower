using System.IO.Compression;
using System.Net;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Output.AzureLogsIngestion;
using Bower.Persistence;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class AdaptiveConcurrencyTests
{
    private static readonly TimeSpan Healthy = TimeSpan.FromMilliseconds(100);

    [Fact]
    public void Controller_StartsAtTheCeilingAndStaysThereWhileHealthy()
    {
        AdaptiveConcurrencyController controller = new(4);

        for (int index = 0; index < 100; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, Healthy);
        }

        // The fixed setting was MaximumConcurrency; the healthy case never runs below it.
        Assert.Equal(4, controller.Limit);
        OutputConcurrencySnapshot snapshot = controller.Snapshot("out", TestEvents.Now);
        Assert.Equal(0, snapshot.Decreases);
        Assert.Equal(100, snapshot.LatencyEwmaMilliseconds);
    }

    [Fact]
    public void Controller_FollowsTheSharedAimdTrace()
    {
        // Same script and expected trace as rust/crates/bower-output-azure/tests/adaptive_concurrency.rs.
        AdaptiveConcurrencyController controller = new(8);
        List<int> trace = [];
        void Step(ConcurrencySignal signal, int milliseconds = 100)
        {
            controller.Complete(controller.BeginAttempt(), signal, TimeSpan.FromMilliseconds(milliseconds));
            trace.Add(controller.Limit);
        }

        for (int index = 0; index < 8; index++) Step(ConcurrencySignal.Healthy);
        Step(ConcurrencySignal.Throttled);
        Step(ConcurrencySignal.Throttled);
        Step(ConcurrencySignal.ServerError);
        Step(ConcurrencySignal.Timeout);
        for (int index = 0; index < 28; index++) Step(ConcurrencySignal.Healthy);
        Step(ConcurrencySignal.Healthy, 400);
        Step(ConcurrencySignal.Neutral);
        // One window: three attempts started under the same limit fail together.
        long[] window = [controller.BeginAttempt(), controller.BeginAttempt(), controller.BeginAttempt()];
        controller.Complete(window[0], ConcurrencySignal.Throttled, Healthy);
        controller.Complete(window[1], ConcurrencySignal.Throttled, Healthy);
        controller.Complete(window[2], ConcurrencySignal.ServerError, Healthy);
        trace.Add(controller.Limit);

        int[] expected =
        [
            8, 8, 8, 8, 8, 8, 8, 8,
            4, 2, 1, 1,
            2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8,
            6, 6,
            3
        ];
        Assert.Equal(expected, trace);
        OutputConcurrencySnapshot snapshot = controller.Snapshot("azure-logs-ingestion", TestEvents.Now);
        Assert.Equal(new OutputConcurrencySnapshot(
            "azure-logs-ingestion", 3, 1, 8, 0, 175, 45, 4, 2, 1, 1, 5, 7, 0, null), snapshot);
    }

    [Fact]
    public void Controller_StaleAttemptsNeitherDecreaseNorIncreaseAgain()
    {
        AdaptiveConcurrencyController controller = new(4);
        long stale = controller.BeginAttempt();
        long alsoStale = controller.BeginAttempt();
        controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Throttled, Healthy);
        Assert.Equal(2, controller.Limit);

        controller.Complete(stale, ConcurrencySignal.ServerError, Healthy);
        controller.Complete(alsoStale, ConcurrencySignal.Healthy, Healthy);

        Assert.Equal(2, controller.Limit);
        OutputConcurrencySnapshot snapshot = controller.Snapshot("out", TestEvents.Now);
        Assert.Equal(1, snapshot.Decreases);
        Assert.Equal(0, snapshot.Increases);
    }

    [Fact]
    public void Controller_JitterBelowTheFloorIsNotASpike()
    {
        AdaptiveConcurrencyController controller = new(4);
        for (int index = 0; index < 4; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, TimeSpan.FromMilliseconds(2));
        }

        // 100x the EWMA but under the absolute floor: fast-link jitter, not congestion.
        controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, TimeSpan.FromMilliseconds(200));

        Assert.Equal(4, controller.Limit);
        Assert.Equal(0, controller.Snapshot("out", TestEvents.Now).LatencySpikes);
    }

    [Fact]
    public void Controller_PersistentLatencyRaisesTheBaselineAndRecovers()
    {
        AdaptiveConcurrencyController controller = new(4);
        for (int index = 0; index < 4; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, Healthy);
        }

        controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, TimeSpan.FromMilliseconds(500));
        Assert.Equal(3, controller.Limit);
        for (int index = 0; index < 20; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, TimeSpan.FromMilliseconds(500));
        }

        // A fivefold step is two spikes (EWMA 100 then 200), then the new baseline is healthy.
        Assert.Equal(4, controller.Limit);
        Assert.Equal(2, controller.Snapshot("out", TestEvents.Now).LatencySpikes);
    }

    [Fact]
    public void Controller_NeverLeavesItsBounds()
    {
        AdaptiveConcurrencyController controller = new(32);
        for (int index = 0; index < 50; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.ServerError, Healthy);
            Assert.InRange(controller.Limit, 1, 32);
        }

        Assert.Equal(1, controller.Limit);
        for (int index = 0; index < 5000; index++)
        {
            controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Healthy, Healthy);
            Assert.InRange(controller.Limit, 1, 32);
        }

        Assert.Equal(32, controller.Limit);
        Assert.Throws<ArgumentOutOfRangeException>(() => new AdaptiveConcurrencyController(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AdaptiveConcurrencyController(33));
    }

    [Theory]
    [InlineData(200, ConcurrencySignal.Healthy)]
    [InlineData(204, ConcurrencySignal.Healthy)]
    [InlineData(429, ConcurrencySignal.Throttled)]
    [InlineData(500, ConcurrencySignal.ServerError)]
    [InlineData(503, ConcurrencySignal.ServerError)]
    [InlineData(408, ConcurrencySignal.Timeout)]
    [InlineData(0, ConcurrencySignal.Timeout)]
    [InlineData(400, ConcurrencySignal.Neutral)]
    [InlineData(401, ConcurrencySignal.Neutral)]
    [InlineData(413, ConcurrencySignal.Neutral)]
    public void Controller_ClassifiesStatuses(int status, ConcurrencySignal expected) =>
        Assert.Equal(expected, AdaptiveConcurrencyController.Classify(status));

    [Fact]
    public void Controller_PauseIsBoundedVisibleAndExpiresOnTheClock()
    {
        FakeClock clock = new(TestEvents.Now);
        AdaptiveConcurrencyController controller = new(4);

        controller.Pause(clock.UtcNow.AddSeconds(-1), clock.UtcNow);
        Assert.Null(controller.PausedUntil(clock.UtcNow));
        controller.Pause(clock.UtcNow.AddSeconds(30), clock.UtcNow);
        controller.Pause(clock.UtcNow.AddSeconds(10), clock.UtcNow);

        Assert.Equal(clock.UtcNow.AddSeconds(30), controller.PausedUntil(clock.UtcNow));
        Assert.Equal(clock.UtcNow.AddSeconds(30), controller.Snapshot("out", clock.UtcNow).ProcessLocalPausedUntil);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Null(controller.PausedUntil(clock.UtcNow));
        OutputConcurrencySnapshot snapshot = controller.Snapshot("out", clock.UtcNow);
        Assert.Null(snapshot.ProcessLocalPausedUntil);
        Assert.Equal(1, snapshot.Pauses);
    }

    [Fact]
    public async Task Controller_AcquireWaitsForASlotAndCancellationLeaksNothing()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        AdaptiveConcurrencyController controller = new(2);
        controller.Complete(controller.BeginAttempt(), ConcurrencySignal.Throttled, Healthy);
        await controller.AcquireAsync(token);

        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task waiting = controller.AcquireAsync(stop.Token).AsTask();
        await Task.Delay(20, token);
        Assert.False(waiting.IsCompleted);
        await stop.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(1, controller.Snapshot("out", TestEvents.Now).InFlight);

        Task next = controller.AcquireAsync(token).AsTask();
        Assert.False(next.IsCompleted);
        controller.Release();
        await next.WaitAsync(TimeSpan.FromSeconds(5), token);
        controller.Release();
        Assert.Equal(0, controller.Snapshot("out", TestEvents.Now).InFlight);
    }

    [Fact]
    public async Task Output_ThrottlingDropsConcurrencyAndRecoversWithoutLosingEvents()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        // Every request carries one ~600 KB record so each event is its own upload.
        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.TooManyRequests, null));
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 8);

        DeliveryResult throttled = await output.DeliverAsync(Events("t", 8), token);

        Assert.Empty(throttled.AcknowledgedEventIds);
        Assert.Equal(8, throttled.Failures.Count);
        Assert.All(throttled.Failures, failure =>
        {
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
        OutputConcurrencySnapshot afterThrottle = output.GetConcurrencySnapshot()!;
        Assert.InRange(afterThrottle.Limit, 1, 4);
        Assert.Equal(8, afterThrottle.Throttles);
        Assert.Equal(0, afterThrottle.InFlight);

        endpoint.Respond = (_, _) => (HttpStatusCode.NoContent, null);
        endpoint.ResetPeak();
        List<string> acknowledged = [];
        for (int round = 0; round < 12; round++)
        {
            DeliveryResult result = await output.DeliverAsync(Events($"r{round}", 8), token);
            Assert.Empty(result.Failures);
            acknowledged.AddRange(result.AcknowledgedEventIds);
        }

        Assert.Equal(96, acknowledged.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(8, output.GetConcurrencySnapshot()!.Limit);
        Assert.InRange(endpoint.Peak, 1, 8);
    }

    [Fact]
    public async Task Output_HealthyThroughputUsesTheFullFixedSetting()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.NoContent, null)) { HoldUntilConcurrent = 4 };
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 4);

        DeliveryResult result = await output.DeliverAsync(Events("h", 8), token);

        Assert.Equal(8, result.AcknowledgedEventIds.Count);
        Assert.Equal(4, endpoint.Peak);
        Assert.Equal(4, output.GetConcurrencySnapshot()!.Limit);
    }

    [Fact]
    public async Task Output_ConcurrencyGateBoundsRequestsInFlightAfterAThrottle()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.ServiceUnavailable, null));
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 8);
        await output.DeliverAsync(Events("burst", 1), token);
        await output.DeliverAsync(Events("burst-2", 1), token);
        await output.DeliverAsync(Events("burst-3", 1), token);
        Assert.Equal(1, output.GetConcurrencySnapshot()!.Limit);

        endpoint.Respond = (_, _) => (HttpStatusCode.NoContent, null);
        endpoint.ResetPeak();
        DeliveryResult result = await output.DeliverAsync(Events("gated", 3), token);

        Assert.Equal(3, result.AcknowledgedEventIds.Count);
        // Limit 1 lets one request out; it then grows to 2 after one healthy attempt.
        Assert.InRange(endpoint.Peak, 1, 2);
        Assert.Equal(3, output.GetConcurrencySnapshot()!.ServerErrors);
    }

    [Fact]
    public async Task Output_RetryAfterPausesTheStreamAndIsVisibleInMetrics()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        FakeClock clock = new(TestEvents.Now);
        ScriptedEndpoint endpoint = new((_, count) => count == 1
            ? (HttpStatusCode.TooManyRequests, "120")
            : (HttpStatusCode.NoContent, null));
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 1, clock: clock);

        DeliveryResult result = await output.DeliverAsync(Events("p", 4), token);

        // The first request was throttled; the rest of the batch was never sent.
        Assert.Equal(1, endpoint.Count);
        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Equal(4, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
            Assert.Equal(clock.UtcNow.AddSeconds(120), failure.RetryAfter);
        });
        Assert.Equal(3, result.Failures.Count(failure => failure.Code == "destination-azure-paused"));
        OutputConcurrencySnapshot snapshot = output.GetConcurrencySnapshot()!;
        Assert.Equal(clock.UtcNow.AddSeconds(120), snapshot.ProcessLocalPausedUntil);
        Assert.Equal(1, snapshot.Pauses);

        clock.Advance(TimeSpan.FromSeconds(121));
        Assert.Null(output.GetConcurrencySnapshot()!.ProcessLocalPausedUntil);
        Assert.Equal(4, (await output.DeliverAsync(Events("p", 4), token)).AcknowledgedEventIds.Count);
    }

    [Fact]
    public async Task Output_ShortRetryAfterDuringSdkRetriesPausesTheStream()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        FakeClock clock = new(TestEvents.Now);
        // The common Azure case: a short Retry-After the SDK honours in memory, then success.
        ScriptedEndpoint endpoint = new((_, count) => count == 1
            ? (HttpStatusCode.TooManyRequests, "1")
            : (HttpStatusCode.NoContent, null))
        { RetryAfterHeader = "retry-after-ms" };
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 1, clock: clock, retries: 2);

        DeliveryResult result = await output.DeliverAsync(Events("s", 3), token);

        // The throttled batch succeeded on its SDK retry; the paused rest was never sent.
        Assert.Equal(2, endpoint.Count);
        Assert.Equal(["s-0"], result.AcknowledgedEventIds);
        Assert.Equal(["s-1", "s-2"], result.Failures.Select(failure => failure.EventId).Order());
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal("destination-azure-paused", failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.Equal(clock.UtcNow.AddMilliseconds(1), failure.RetryAfter);
        });
        OutputConcurrencySnapshot snapshot = output.GetConcurrencySnapshot()!;
        Assert.Equal(1, snapshot.Pauses);
        Assert.Equal(1, snapshot.Throttles);
        Assert.Equal(clock.UtcNow.AddMilliseconds(1), snapshot.ProcessLocalPausedUntil);
    }

    [Fact]
    public async Task Output_DeliveryScopeBoundsEachDeliveryNotTheWholeOutput()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        // Eight concurrent single-event deliveries must all be in flight together.
        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.NoContent, null)) { HoldUntilConcurrent = 8 };
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 4, scope: ConcurrencyScope.Delivery);

        DeliveryResult[] results = await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(index => output.DeliverAsync(Events($"d{index}", 1), token)));

        Assert.All(results, result => Assert.Single(result.AcknowledgedEventIds));
        Assert.Equal(8, endpoint.Peak);
        // No shared controller: nothing output-wide to report.
        Assert.Null(output.GetConcurrencySnapshot());
    }

    [Fact]
    public async Task Output_LatencySpikeReducesConcurrency()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        ManualTimestamps clock = new();
        ScriptedEndpoint endpoint = new((_, count) =>
        {
            clock.Advance(TimeSpan.FromMilliseconds(count <= 4 ? 50 : 500));
            return (HttpStatusCode.NoContent, null);
        });
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 4, clock: clock);

        for (int index = 0; index < 5; index++)
        {
            await output.DeliverAsync(Events($"l{index}", 1), token);
        }

        OutputConcurrencySnapshot snapshot = output.GetConcurrencySnapshot()!;
        Assert.Equal(3, snapshot.Limit);
        Assert.Equal(1, snapshot.LatencySpikes);
        Assert.Equal(163, snapshot.LatencyEwmaMilliseconds);
    }

    [Fact]
    public async Task Output_CancellationWhileWaitingForASlotNeverAcknowledges()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.NoContent, null))
        {
            BeforeRespond = async cancellation =>
            {
                entered.TrySetResult();
                await Task.Delay(Timeout.Infinite, cancellation);
            }
        };
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 1);
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(token);

        Task<DeliveryResult> delivery = output.DeliverAsync(Events("c", 3), stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), token);
        await stop.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => delivery);
        Assert.Equal(1, endpoint.Count);
        Assert.Equal(0, output.GetConcurrencySnapshot()!.InFlight);
    }

    [Fact]
    public async Task Worker_DeadlineCancelsSdkRequestAndRetainsWholeBatchForRetry()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManualTimeProvider clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 64 * 1024 * 1024, clock);
        await store.InitializeAsync(token);
        foreach (QueuedEvent item in Events("deadline", 3))
        {
            await store.EnqueueAsync(item, token);
        }

        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.NoContent, null))
        {
            BeforeRespond = async cancellation =>
            {
                entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellation);
            }
        };
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 1, clock: clock);
        using QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions
        {
            MaximumDeliveryAttempts = 1,
            LeaseDuration = TimeSpan.FromSeconds(90),
            DeliveryTimeout = TimeSpan.FromSeconds(60)
        }, NullLogger<QueueDeliveryWorker>.Instance);

        Task<int> delivery = worker.DeliverOnceAsync(token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), token);
        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(3, await delivery.WaitAsync(TimeSpan.FromSeconds(10), token));

        QueueSnapshot snapshot = await store.GetSnapshotAsync(token);
        Assert.Equal((3L, 0L, 0L, 0L),
            (snapshot.Retrying, snapshot.Uploading, snapshot.Delivered, snapshot.DeadLettered));
        Assert.Equal(0, output.GetConcurrencySnapshot()!.InFlight);
        Assert.Equal(1, endpoint.Count);
        Assert.True((await store.VerifyLedgerAsync(token)).Intact);
    }

    [Fact]
    public async Task Worker_ThrottledEventsStayDurableAndDeliverOnceWithoutPrematureAck()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 64 * 1024 * 1024, clock);
        await store.InitializeAsync(token);
        foreach (QueuedEvent item in Events("w", 6))
        {
            await store.EnqueueAsync(item, token);
        }

        ScriptedEndpoint endpoint = new((_, _) => (HttpStatusCode.TooManyRequests, "60"));
        AzureLogsIngestionOutput output = CreateOutput(endpoint, maximumConcurrency: 2, clock: clock);
        QueueDeliveryWorker worker = new(store, output, clock,
            new QueueDeliveryOptions { MaximumDeliveryAttempts = 1 }, NullLogger<QueueDeliveryWorker>.Instance);

        Assert.Equal(6, await worker.DeliverOnceAsync(token));
        QueueSnapshot throttled = await store.GetSnapshotAsync(token);
        Assert.Equal(6, throttled.Retrying);
        Assert.Equal(0, throttled.Delivered);
        Assert.Equal(0, throttled.DeadLettered);
        // The durable destination circuit holds the stream for the Retry-After window.
        Assert.Equal(0, await worker.DeliverOnceAsync(token));
        // Up to two requests were in flight before the pause; the rest were never sent.
        int throttledRequests = endpoint.Count;
        Assert.InRange(throttledRequests, 1, 2);

        endpoint.Respond = (_, _) => (HttpStatusCode.NoContent, null);
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(6, await worker.DeliverOnceAsync(token));
        QueueSnapshot delivered = await store.GetSnapshotAsync(token);
        Assert.Equal(6, delivered.Delivered);
        Assert.Equal(0, delivered.DeadLettered);
        Assert.Equal(0, delivered.Retrying + delivered.Queued + delivered.Uploading);
        Assert.Equal(throttledRequests + 6, endpoint.Count);
    }

    private static QueuedEvent[] Events(string prefix, int count)
    {
        string padding = new('x', 600 * 1024);
        return Enumerable.Range(0, count).Select(index =>
        {
            string eventId = $"{prefix}-{index}";
            return new QueuedEvent(
                eventId,
                $"sha256:{eventId}",
                JsonSerializer.Serialize(new { eventId, timeGenerated = "2026-10-08T00:00:00Z", padding }),
                TestEvents.Now);
        }).ToArray();
    }

    private static AzureLogsIngestionOutput CreateOutput(
        HttpMessageHandler handler,
        int maximumConcurrency,
        TimeProvider? clock = null,
        int retries = 0,
        ConcurrencyScope scope = ConcurrencyScope.Output)
    {
        LogsIngestionClientOptions clientOptions = new()
        {
            Transport = new HttpClientTransport(new HttpClient(handler)),
            Retry = { MaxRetries = retries, Delay = TimeSpan.FromMilliseconds(1), MaxDelay = TimeSpan.FromMilliseconds(10) }
        };
        return new AzureLogsIngestionOutput(
            new AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = new Uri("https://example.ingest.monitor.azure.com"),
                DcrImmutableId = "dcr-00000000000000000000000000000000",
                StreamName = "Custom-BowerSecurity",
                MaximumConcurrency = maximumConcurrency,
                ConcurrencyScope = scope
            },
            new StaticCredential(),
            clientOptions,
            // Default: monotonic time stands still, so real scheduling jitter is never a latency spike.
            clock ?? new ManualTimestamps());
    }

    /// <summary>Fake ingestion endpoint: scripted status and Retry-After, peak concurrency.</summary>
    private sealed class ScriptedEndpoint(Func<string[], int, (HttpStatusCode Status, string? RetryAfter)> respond)
        : HttpMessageHandler
    {
        private readonly object gate = new();
        private readonly TaskCompletionSource concurrent = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int count;
        private int inFlight;

        public Func<string[], int, (HttpStatusCode Status, string? RetryAfter)> Respond { get; set; } = respond;

        public Func<CancellationToken, Task>? BeforeRespond { get; init; }

        public int HoldUntilConcurrent { get; init; }

        public string RetryAfterHeader { get; init; } = "Retry-After";

        public int Count => Volatile.Read(ref count);

        public int Peak { get; private set; }

        public void ResetPeak()
        {
            lock (gate) Peak = 0;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            byte[] compressed = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            using GZipStream gzip = new(new MemoryStream(compressed), CompressionMode.Decompress);
            using MemoryStream plain = new();
            await gzip.CopyToAsync(plain, cancellationToken);
            using JsonDocument document = JsonDocument.Parse(plain.ToArray());
            string[] eventIds = document.RootElement.EnumerateArray()
                .Select(item => item.GetProperty("eventId").GetString()!)
                .ToArray();
            int number = Interlocked.Increment(ref count);
            lock (gate)
            {
                inFlight++;
                Peak = Math.Max(Peak, inFlight);
                if (inFlight >= HoldUntilConcurrent) concurrent.TrySetResult();
            }

            try
            {
                if (HoldUntilConcurrent > 0)
                {
                    await concurrent.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
                }

                if (BeforeRespond is not null) await BeforeRespond(cancellationToken);
                (HttpStatusCode status, string? retryAfter) = Respond(eventIds, number);
                HttpResponseMessage response = new(status) { Content = new StringContent("{}") };
                if (retryAfter is not null) response.Headers.TryAddWithoutValidation(RetryAfterHeader, retryAfter);
                return response;
            }
            finally
            {
                lock (gate) inFlight--;
            }
        }
    }

    /// <summary>Wall clock pinned to <see cref="TestEvents.Now"/>; monotonic time moves only when told.</summary>
    private sealed class ManualTimestamps : TimeProvider
    {
        private long ticks;

        public override DateTimeOffset GetUtcNow() => TestEvents.Now;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Read(ref ticks);

        public void Advance(TimeSpan duration) => Interlocked.Add(ref ticks, duration.Ticks);
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}
