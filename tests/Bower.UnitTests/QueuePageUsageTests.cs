using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;

namespace Bower.UnitTests;

public sealed class QueuePageUsageTests
{
    private const string Token = "queue-pages-test-token-0123456789abcdef";

    [Fact]
    public async Task PageUsage_FallsAfterRetentionWhileTheFileKeepsItsSize()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 4_194_304, clock);
        await store.InitializeAsync(cancellationToken);
        string payload = $$"""{"v":"{{new string('x', 1_000)}}"}""";
        for (int index = 0; index < 1_500; index++)
        {
            await store.EnqueueAsync(new QueuedEvent($"e{index:0000}", $"sha256:{index:0000}", payload, clock.UtcNow), cancellationToken);
        }

        IReadOnlyList<QueuedEvent> leased;
        while ((leased = await store.LeaseAsync(500, TimeSpan.FromMinutes(1), cancellationToken)).Count > 0)
        {
            await store.MarkDeliveredBatchAsync(
                [.. leased.Select(item => item.EventId)], "ack", leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), cancellationToken);
        }

        QueuePageUsage full = await store.GetPageUsageAsync(cancellationToken);
        long fileBefore = new FileInfo(path).Length;
        clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(1_500, await store.PurgeDeliveredAsync(clock.UtcNow, 10_000, cancellationToken));
        QueuePageUsage drained = await store.GetPageUsageAsync(cancellationToken);

        // The limit is the store's own max_page_count: (4 x cap + 16 MiB) / 4.
        Assert.Equal((4_194_304L * 4 + 16_777_216) / 4, full.PageLimitBytes);
        Assert.Equal(full.PageLimitBytes, drained.PageLimitBytes);
        Assert.True(full.UsedBytes > 1_500_000, $"{full.UsedBytes}");
        // No vacuum: the file does not shrink, but the freed pages are on the free list.
        Assert.True(new FileInfo(path).Length >= fileBefore);
        Assert.True(drained.FreeListBytes > 1_000_000, $"{drained.FreeListBytes}");
        Assert.True(drained.UsedBytes < full.UsedBytes / 2, $"{drained.UsedBytes} vs {full.UsedBytes}");
        Assert.True(drained.UsedPercent < full.UsedPercent);
        Assert.Equal(drained.PageCount * drained.PageSize, drained.UsedBytes + drained.FreeListBytes);
    }

    [Fact]
    public void PageUsage_PercentIsBoundedAndSafeWithoutALimit()
    {
        Assert.Equal(50.0, new QueuePageUsage(4_096, 60, 10, 100).UsedPercent);
        Assert.Equal(100.0, new QueuePageUsage(4_096, 120, 0, 100).UsedPercent);
        Assert.Equal(0, new QueuePageUsage(4_096, 10, 20, 100).UsedBytes);
        Assert.Equal(0, new QueuePageUsage(4_096, 10, 0, 0).UsedPercent);
    }

    [Fact]
    public async Task Status_ReportsQueuePagesAndLivenessTouchesNoStorage()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = CollectorApplication.Build(
            new CollectorSettings
            {
                ListenUrl = "http://127.0.0.1:4319",
                QueuePath = Path.Combine(directory.Path, "queue.db"),
                PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
                CollectorId = "queue-pages-test",
                SingleTrustDomain = true,
                IngestToken = Token,
                MaximumQueueBytes = 4_194_304
            },
            builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();

        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(request, cancellationToken);
        using JsonDocument body = JsonDocument.Parse(await status.Content.ReadAsStringAsync(cancellationToken));
        JsonElement pages = body.RootElement.GetProperty("queuePages");
        Assert.Equal(8_388_608, pages.GetProperty("pageLimitBytes").GetInt64());
        Assert.True(pages.GetProperty("usedBytes").GetInt64() > 0);
        Assert.True(pages.GetProperty("freeListBytes").GetInt64() >= 0);
        Assert.True(pages.GetProperty("usedPercent").GetDouble() is > 0 and < 100);
        Assert.Equal(4_096, pages.GetProperty("pageSize").GetInt64());
        JsonElement activity = body.RootElement.GetProperty("deliveryActivity");
        Assert.Equal(JsonValueKind.Null, activity.GetProperty("lastFailureCode").ValueKind);
        Assert.Equal(JsonValueKind.Null, activity.GetProperty("lastSuccessfulDeliveryAt").ValueKind);

        // Liveness answers even when the queue database is gone: it never opens storage.
        await app.StopAsync(cancellationToken);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        await using WebApplication orphan = CollectorApplication.Build(
            new CollectorSettings
            {
                ListenUrl = "http://127.0.0.1:4319",
                QueuePath = Path.Combine(directory.Path, "missing", "queue.db"),
                PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
                CollectorId = "queue-pages-test",
                SingleTrustDomain = true
            },
            builder => builder.WebHost.UseTestServer());
        await orphan.StartAsync(cancellationToken);
        using HttpResponseMessage live = await orphan.GetTestClient().GetAsync("/health/live", cancellationToken);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal("""{"status":"alive"}""", await live.Content.ReadAsStringAsync(cancellationToken));
        await orphan.StopAsync(cancellationToken);
    }
}
