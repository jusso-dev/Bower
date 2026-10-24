using Bower.Sdk;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

public sealed class SdkDeliveryTests
{
    [Fact]
    public async Task Saturation_RejectsOverflowAndAccountsForEveryAcceptedItem()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using WebApplication server = await Server(async context =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(context.RequestAborted);
            context.Response.StatusCode = 200;
        });
        await using ServiceProvider services = Client(server, options => options.BufferCapacity = 1);
        IBowerTelemetry client = services.GetRequiredService<IBowerTelemetry>();
        Assert.True((await Emit(client)).AcceptedForDelivery);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.True((await Emit(client)).AcceptedForDelivery);
        Assert.Equal("bounded-buffer-full", (await Emit(client)).FailureCode);
        Assert.Equal(2, Snapshot(client).Pending);
        release.TrySetResult();
        await Until(() => Snapshot(client).Delivered == 2);
        await services.DisposeAsync();
        Assert.Equal(new DeliveryStatus(2, 2, 0, 0, 1, 0, "sender-stopped", null), Snapshot(client));
    }

    [Theory]
    [InlineData(422, 1, 0, 1)]
    [InlineData(429, 3, 1, 0)]
    [InlineData(503, 3, 1, 0)]
    public async Task HttpFailures_AreObservableAndTransientFailuresRecover(int status, int requests, int delivered, int failed)
    {
        int calls = 0;
        await using WebApplication server = await Server(context =>
        {
            context.Response.StatusCode = Interlocked.Increment(ref calls) < 3 ? status : 200;
            return Task.CompletedTask;
        });
        await using ServiceProvider services = Client(server);
        IBowerTelemetry client = services.GetRequiredService<IBowerTelemetry>();
        Assert.True((await Emit(client)).AcceptedForDelivery);
        await Until(() => Snapshot(client).Pending == 0);
        DeliveryStatus snapshot = Snapshot(client);
        Assert.Equal(requests, calls);
        Assert.Equal(delivered, snapshot.Delivered);
        Assert.Equal(failed, snapshot.Failed);
        Assert.Equal($"collector-http-{status}", snapshot.LastFailureCode);
        Assert.Equal(snapshot.Accepted, snapshot.Delivered + snapshot.Failed + snapshot.Pending);
    }

    [Fact]
    public async Task StrictFailure_ClosesWriterAndRejectsLaterProducers()
    {
        await using WebApplication server = await Server(context =>
        {
            context.Response.StatusCode = 422;
            return Task.CompletedTask;
        });
        await using ServiceProvider services = Client(server, options => options.FailApplicationOnTelemetryFailure = true);
        IBowerTelemetry client = services.GetRequiredService<IBowerTelemetry>();
        await Emit(client);
        await Until(() => Snapshot(client).SenderState == "sender-faulted");
        BowerDeliveryException exception = await Assert.ThrowsAsync<BowerDeliveryException>(async () => await Emit(client));
        Assert.Contains("sender-faulted", exception.Message, StringComparison.Ordinal);
        Assert.Equal(1, Snapshot(client).Failed);
        Assert.Equal(1, Snapshot(client).Rejected);
    }

    [Fact]
    public async Task ShutdownTimeout_AccountsForInflightAndBufferedItems()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using WebApplication server = await Server(async context =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, context.RequestAborted);
        });
        ServiceProvider services = Client(server, options => options.ShutdownFlushTimeout = TimeSpan.FromMilliseconds(100));
        IBowerTelemetry client = services.GetRequiredService<IBowerTelemetry>();
        await Emit(client);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        await Emit(client);
        await services.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(2, Snapshot(client).Failed);
        Assert.Equal(0, Snapshot(client).Pending);
        Assert.Equal("shutdown-timeout", Snapshot(client).LastFailureCode);
        Assert.False((await Emit(client)).AcceptedForDelivery);
    }

    [Fact]
    public async Task RequestTimeout_ExhaustsBoundedRetriesWithVisibleFailure()
    {
        await using WebApplication server = await Server(context => Task.Delay(Timeout.InfiniteTimeSpan, context.RequestAborted));
        await using ServiceProvider services = Client(server, options => options.LocalCollector.RequestTimeout = TimeSpan.FromMilliseconds(50));
        IBowerTelemetry client = services.GetRequiredService<IBowerTelemetry>();
        await Emit(client);
        await Until(() => Snapshot(client).Failed == 1);
        Assert.Equal(2, Snapshot(client).Retries);
        Assert.Equal("collector-unavailable", Snapshot(client).LastFailureCode);
    }

    private static DeliveryStatus Snapshot(IBowerTelemetry client) =>
        ((IBowerTelemetryDiagnostics)client).DeliveryStatus;

    private static ValueTask<EmitResult> Emit(IBowerTelemetry client) => client.AuthenticationFailedAsync(new AuthenticationFailedEvent
    {
        Username = "test-user",
        FailureReason = "test-failure",
        CorrelationId = Guid.NewGuid().ToString()
    }, TestContext.Current.CancellationToken);

    private static ServiceProvider Client(WebApplication server, Action<BowerOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddBower(options =>
        {
            options.Application.Name = "test";
            options.Application.Environment = "test";
            options.LocalCollector.Endpoint = server.Urls.Single();
            options.RetryDelay = TimeSpan.FromMilliseconds(1);
            configure?.Invoke(options);
        });
        return services.BuildServiceProvider();
    }

    private static async Task<WebApplication> Server(RequestDelegate handler)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        WebApplication app = builder.Build();
        app.Urls.Add("http://127.0.0.1:0");
        app.MapPost("/v1/events", handler);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task Until(Func<bool> condition)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(10, timeout.Token);
    }
}
