using System.Net;
using Bower.Abstractions;
using Bower.Forwarding;

namespace Bower.UnitTests;

public sealed class RelayResponseTimeoutTests
{
    [Fact]
    public async Task StalledResponseBodyHoldsEveryBatchForRetryWithoutAcknowledgement()
    {
        using CancellationTokenSource safety = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        safety.CancelAfter(TimeSpan.FromSeconds(5));
        using StalledResponseHandler handler = new();
        using HttpClient client = new(handler)
        {
            BaseAddress = new Uri("https://relay.example.test"),
            Timeout = TimeSpan.FromMilliseconds(100)
        };
        RelayOutput output = new(client, "edge-01");
        QueuedEvent[] events = [.. Enumerable.Range(0, RelayProtocol.MaximumBatchEvents + 1)
            .Select(index => new QueuedEvent($"e{index}", $"f{index}", "{}", DateTimeOffset.UtcNow))];

        DeliveryResult result = await output.DeliverAsync(events, safety.Token);

        Assert.Equal(1, handler.Requests);
        Assert.True(handler.BodyReadStarted.Task.IsCompletedSuccessfully);
        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Null(result.DestinationAcknowledgement);
        Assert.Equal(events.Length, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal("destination-relay-unavailable", failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
    }

    [Fact]
    public async Task CallerCancellationDuringResponseBodyPropagates()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using StalledResponseHandler handler = new();
        using HttpClient client = new(handler) { BaseAddress = new Uri("https://relay.example.test") };
        RelayOutput output = new(client, "edge-01");
        Task<DeliveryResult> delivery = output.DeliverAsync(
            [new QueuedEvent("e1", "f1", "{}", DateTimeOffset.UtcNow)], cancellation.Token);
        await handler.BodyReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => delivery);
    }

    private sealed class StalledResponseHandler : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public TaskCompletionSource BodyReadStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new StalledBody(BodyReadStarted))
            });
        }
    }

    private sealed class StalledBody(TaskCompletionSource started) : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}
