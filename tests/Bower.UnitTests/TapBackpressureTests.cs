using System.Net;
using System.Net.Http.Headers;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class TapBackpressureTests
{
    [Theory]
    [InlineData(0)] // The start frame cannot be written.
    [InlineData(3)] // The start frame fits, but the first event cannot be written.
    public async Task StalledResponse_ReleasesSessionAtDeadline(int successfulWrites)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using StalledStream body = new(successfulWrites);
        const string token = "tap-backpressure-test-token-0123456789";
        await using WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "tap-backpressure-test",
            IngestToken = token,
            TapMaximumDurationSeconds = 1
        }, builder => builder.WebHost.UseTestServer());
        app.Use((context, next) =>
        {
            context.Response.Body = body;
            return next(context);
        });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        EventTap tap = app.Services.GetRequiredService<EventTap>();
        using HttpClient client = app.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/tap");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Task<HttpResponseMessage> response = client.SendAsync(request, cancellation);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!tap.IsActive)
        {
            await Task.Delay(10, timeout.Token);
        }

        tap.Publish(new ProcessingResult(DecisionAction.Accept, "test", true, false, [], null), null, "{}");
        await body.Blocked.Task.WaitAsync(timeout.Token);
        using HttpResponseMessage completed = await response.WaitAsync(timeout.Token);
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        Assert.False(tap.IsActive);
        Assert.False(cancellation.IsCancellationRequested);
    }

    private sealed class StalledStream(int successfulWrites) : MemoryStream
    {
        private int writes;
        public TaskCompletionSource Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref writes) > successfulWrites)
            {
                Blocked.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            await base.WriteAsync(buffer, cancellationToken);
        }
    }
}
