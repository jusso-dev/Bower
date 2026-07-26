using System.Globalization;
using Bower.Management.Api;

namespace Bower.UnitTests;

public sealed class ManagementStoreTests
{
    [Fact]
    public async Task Registration_requires_approval_before_heartbeat()
    {
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        DateTimeOffset now = DateTimeOffset.Parse(
            "2026-07-26T01:00:00Z",
            CultureInfo.InvariantCulture);
        CollectorRegistration registration = Registration();

        CollectorRecord pending = await store.RegisterAsync(
            registration,
            "service-principal-1",
            now,
            TestContext.Current.CancellationToken);

        Assert.Equal(CollectorStatus.Pending, pending.Status);
        await Assert.ThrowsAsync<CollectorStateException>(
            () => store.HeartbeatAsync(
                registration.CollectorId,
                Heartbeat(),
                "service-principal-1",
                now.AddMinutes(1),
                TestContext.Current.CancellationToken));

        ApprovalRecord? approval = await store.DecideAsync(
            registration.CollectorId,
            CollectorStatus.Approved,
            "approved",
            "Matched approved change BWR-142.",
            "approver-object-id",
            "Ari Singh",
            now.AddMinutes(2),
            TestContext.Current.CancellationToken);
        CollectorRecord? active = await store.HeartbeatAsync(
            registration.CollectorId,
            Heartbeat(),
            "service-principal-1",
            now.AddMinutes(3),
            TestContext.Current.CancellationToken);

        Assert.NotNull(approval);
        Assert.NotNull(active);
        Assert.Equal(CollectorStatus.Active, active.Status);
        Assert.Equal(7, active.QueueDepth);
        Assert.Equal(
            2,
            (await store.ListAuditAsync(TestContext.Current.CancellationToken)).Count);

        await Assert.ThrowsAsync<CollectorStateException>(
            () => store.DecideAsync(
                registration.CollectorId,
                CollectorStatus.Approved,
                "approved",
                "Duplicate approval.",
                "approver-object-id",
                "Ari Singh",
                now.AddMinutes(4),
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Registration_cannot_rebind_collector_identity()
    {
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        CollectorRegistration registration = Registration();
        await store.RegisterAsync(
            registration,
            "service-principal-1",
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<CollectorIdentityConflictException>(
            () => store.RegisterAsync(
                registration,
                "service-principal-2",
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken));
    }

    private static CollectorRegistration Registration() =>
        new(
            "finance-collector-01",
            "finance-app-01",
            "production",
            "0.1.0",
            "sha256:configuration",
            "sha256:policy",
            [new SourceReport("legacy-finance", "sqlserver", "healthy", 4, null)],
            [new OutputReport("sentinel", "azure-logs-ingestion", "healthy", null, null)]);

    private static CollectorHeartbeat Heartbeat() =>
        new(
            "0.1.0",
            "sha256:configuration",
            "sha256:policy",
            7,
            "healthy",
            [new SourceReport("legacy-finance", "sqlserver", "healthy", 2, null)],
            [new OutputReport("sentinel", "azure-logs-ingestion", "healthy", null, null)]);
}
