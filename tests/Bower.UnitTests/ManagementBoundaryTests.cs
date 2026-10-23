using Bower.Management.Api;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class ManagementBoundaryTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public async Task Invalid_counters_are_rejected_without_inventory_writes(long count)
    {
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        CancellationToken ct = TestContext.Current.CancellationToken;
        await store.InitializeAsync(ct);
        await store.RegisterAsync(Registration("one"), "principal", TestEvents.Now, ct);
        await store.DecideAsync("one", CollectorStatus.Approved, "approved", "test", "admin", "admin", TestEvents.Now, ct);
        CollectorRecord? before = await store.GetAsync("one", ct);

        await Assert.ThrowsAsync<ArgumentException>(() => store.HeartbeatAsync("one",
            Heartbeat() with { QueueDepth = count }, "principal", TestEvents.Now.AddMinutes(1), ct));
        await Assert.ThrowsAsync<ArgumentException>(() => store.HeartbeatAsync("one",
            Heartbeat() with { DeadLettered = count }, "principal", TestEvents.Now.AddMinutes(1), ct));
        CollectorRecord? after = await store.GetAsync("one", ct);
        Assert.Equal(before!.LastSeenAt, after!.LastSeenAt);
        Assert.Equal(before.QueueDepth, after.QueueDepth);
        Assert.Equal(before.Status, after.Status);
    }

    [Theory]
    [InlineData(CollectorStatus.Suspended, "suspended")]
    [InlineData(CollectorStatus.Revoked, "revoked")]
    public async Task Disabled_identity_cannot_rewrite_inventory_and_denial_is_audited(CollectorStatus status, string action)
    {
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        CancellationToken ct = TestContext.Current.CancellationToken;
        await store.InitializeAsync(ct);
        await store.RegisterAsync(Registration("one"), "principal", TestEvents.Now, ct);
        await store.DecideAsync("one", CollectorStatus.Approved, "approved", "test", "admin", "admin", TestEvents.Now, ct);
        await store.DecideAsync("one", status, action, "test", "admin", "admin", TestEvents.Now, ct);
        CollectorRecord? before = await store.GetAsync("one", ct);

        await Assert.ThrowsAsync<CollectorStateException>(() => store.RegisterAsync(
            Registration("one") with { MachineName = "forged", PolicyHash = "forged", Sources = [] },
            "principal", TestEvents.Now.AddMinutes(1), ct));

        CollectorRecord? after = await store.GetAsync("one", ct);
        Assert.Equal(before!.MachineName, after!.MachineName);
        Assert.Equal(before.PolicyHash, after.PolicyHash);
        Assert.Equal(before.LastSeenAt, after.LastSeenAt);
        Assert.Equal(before.Sources, after.Sources);
        Assert.Contains(await store.ListAuditAsync(ct), item => item.Action == "collector.registration-denied");
    }

    [Fact]
    public async Task Legacy_extreme_rows_cannot_overflow_overview()
    {
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "management.db");
        ManagementStore store = new(path);
        CancellationToken ct = TestContext.Current.CancellationToken;
        await store.InitializeAsync(ct);
        foreach (string id in new[] { "one", "two" })
            await store.RegisterAsync(Registration(id), "principal", TestEvents.Now, ct);
        await using SqliteConnection connection = new($"Data Source={path}");
        await connection.OpenAsync(ct);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "UPDATE collectors SET queue_depth = $count, dead_lettered = $count;";
        command.Parameters.AddWithValue("$count", long.MaxValue);
        await command.ExecuteNonQueryAsync(ct);

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now.AddMinutes(-1), ct);
        Assert.Equal(long.MaxValue, overview.TotalQueueDepth);
        Assert.Equal(long.MaxValue, overview.DeadLettered);
    }

    [Fact]
    public async Task Null_and_duplicate_reports_are_controlled_validation_errors()
    {
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        CancellationToken ct = TestContext.Current.CancellationToken;
        await store.InitializeAsync(ct);
        await Assert.ThrowsAsync<ArgumentException>(() => store.RegisterAsync(
            Registration("one") with { Sources = null! }, "principal", TestEvents.Now, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => store.RegisterAsync(
            Registration("one") with { Sources = [null!] }, "principal", TestEvents.Now, ct));
        SourceReport source = new("same", "sql", "healthy", null, null);
        await Assert.ThrowsAsync<ArgumentException>(() => store.RegisterAsync(
            Registration("one") with { Sources = [source, source] }, "principal", TestEvents.Now, ct));
        Assert.Empty(await store.ListAsync(null, ct));
    }

    private static CollectorRegistration Registration(string id) =>
        new(id, "machine", "test", "1", "config", "policy", [new("source", "sql", "healthy", 0, null)], []);

    private static CollectorHeartbeat Heartbeat() => new("1", "config", "policy", 0, "healthy", [], []);
}
