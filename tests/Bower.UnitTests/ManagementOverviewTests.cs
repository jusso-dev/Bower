using System.Net;
using System.Net.Http.Json;
using Bower.Management.Api;
using Bower.Management.Api.Jobs;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// Fleet overview projection: privacy profile drift (#69) and reporting coverage gated on
/// collector lifecycle and heartbeat freshness at query time (#70).
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class ManagementOverviewTests
{
    private static readonly TimeSpan StaleAfter = CollectorStalenessJob.StaleAfter;

    [Fact]
    public async Task PrivacyDrift_FreshHeartbeatWithPriorHashIsAnActionableException()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct, "default");
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        DateTimeOffset assignedAt = TestEvents.Now.AddMinutes(1);
        await store.AssignPrivacyProfileAsync("edge-01", version.Id, "Roll out", "admin", "Admin", assignedAt, ct);
        // One poll interval plus margin after the assignment, the collector still reports
        // the built-in default: it rejected the deployment.
        DateTimeOffset observedAt = assignedAt + PrivacyProfileDriftRecord.ConfirmationDelay;
        await store.HeartbeatAsync("edge-01", Heartbeat("default"), "principal", observedAt, ct);

        OverviewRecord overview = await store.OverviewAsync(observedAt - StaleAfter, ct);

        Assert.Equal(1, overview.PrivacyProfileDrift);
        Assert.Equal("edge-01", Assert.Single(overview.Exceptions).Id);
        // Delivery and heartbeat health are otherwise normal.
        Assert.Equal(0, overview.UnhealthyCollectors);
        Assert.Equal(0, overview.StaleCollectors);
        Assert.Equal(0, overview.PolicyDrift);
        PrivacyProfileDriftRecord drift = Assert.Single(overview.PrivacyProfileExceptions!);
        Assert.Equal("edge-01", drift.CollectorId);
        Assert.Equal("edge-01", drift.MachineName);
        Assert.True(drift.AssignmentRevision > 0);
        Assert.Equal(assignedAt, drift.AssignedAt);
        Assert.Equal((version.Id, "contoso-app", "1.0.0"), (drift.VersionId, drift.ProfileId, drift.Version));
        Assert.Equal(version.ContentHash, drift.AssignedHash);
        Assert.Equal("default", drift.ObservedHash);
        Assert.Equal(observedAt, drift.ObservedAt);
        Assert.True(drift.MismatchConfirmed);
    }

    [Fact]
    public async Task PrivacyDrift_HeartbeatWithinTheConfirmationDelayIsAwaitingNotFailed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct, "default");
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        await store.AssignPrivacyProfileAsync("edge-01", version.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);
        // The heartbeat and privacy-profile jobs run independently every minute: this
        // heartbeat may simply precede the collector's next deployment poll.
        DateTimeOffset observedAt = TestEvents.Now
            + PrivacyProfileDriftRecord.ConfirmationDelay - TimeSpan.FromSeconds(1);
        await store.HeartbeatAsync("edge-01", Heartbeat("default"), "principal", observedAt, ct);

        OverviewRecord overview = await store.OverviewAsync(observedAt - StaleAfter, ct);

        PrivacyProfileDriftRecord drift = Assert.Single(overview.PrivacyProfileExceptions!);
        Assert.False(drift.MismatchConfirmed);
        Assert.Equal(observedAt, drift.ObservedAt);
        Assert.Equal(TimeSpan.FromMinutes(2), PrivacyProfileDriftRecord.ConfirmationDelay);
    }

    [Fact]
    public async Task PrivacyDrift_RowWithoutAMatchingAssignmentHistoryRowIsOmittedNotZeroFilled()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "management.db");
        ManagementStore store = new(path);
        await store.InitializeAsync(ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct, "default");
        await ActiveAsync(store, "edge-02", TestEvents.Now, ct, "default");
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        await store.AssignPrivacyProfileAsync("edge-01", version.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);
        await store.AssignPrivacyProfileAsync("edge-02", version.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(ct);
            await using SqliteCommand command = connection.CreateCommand();
            // edge-01: history row missing. edge-02: the latest history row clears the
            // assignment, so it does not describe the version the collector row still holds.
            command.CommandText =
                """
                DELETE FROM privacy_profile_assignments WHERE collector_id = 'edge-01';
                INSERT INTO privacy_profile_assignments (
                    collector_id, version_id, action, reason, actor_object_id, actor_name, occurred_at)
                VALUES ('edge-02', NULL, 'cleared', 'Race', 'admin', 'Admin', '2026-07-26T02:20:19.0000000+00:00');
                """;
            await command.ExecuteNonQueryAsync(ct);
        }

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now - StaleAfter, ct);

        // Both still drift and stay exceptions; neither gets a fabricated revision or time.
        Assert.Equal(2, overview.PrivacyProfileDrift);
        Assert.Equal(2, overview.Exceptions.Count);
        Assert.Empty(overview.PrivacyProfileExceptions!);
    }

    [Fact]
    public async Task PrivacyDrift_HeartbeatBeforeAssignmentIsNotYetConfirmed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct, "default");
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        await store.AssignPrivacyProfileAsync(
            "edge-01", version.Id, "Roll out", "admin", "Admin", TestEvents.Now.AddMinutes(1), ct);

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now.AddMinutes(1) - StaleAfter, ct);

        // Desired assignment differs from the last observation, which predates it.
        PrivacyProfileDriftRecord drift = Assert.Single(overview.PrivacyProfileExceptions!);
        Assert.False(drift.MismatchConfirmed);
        Assert.Equal(1, overview.PrivacyProfileDrift);
    }

    [Fact]
    public async Task PrivacyDrift_MatchingHashClearsAndUnassignedCollectorIsUnaffected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct, "default");
        await ActiveAsync(store, "edge-02", TestEvents.Now, ct, "default");
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        await store.AssignPrivacyProfileAsync("edge-01", version.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);
        DateTimeOffset later = TestEvents.Now.AddMinutes(2);
        await store.HeartbeatAsync("edge-01", Heartbeat(version.ContentHash), "principal", later, ct);
        await store.HeartbeatAsync("edge-02", Heartbeat("default"), "principal", later, ct);

        OverviewRecord overview = await store.OverviewAsync(later - StaleAfter, ct);

        Assert.Equal(0, overview.PrivacyProfileDrift);
        Assert.Empty(overview.PrivacyProfileExceptions!);
        Assert.Empty(overview.Exceptions);
    }

    [Fact]
    public async Task PrivacyDrift_OverviewJsonCarriesNoProfileContentOrKeyMaterial()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, ct);
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator, "carol");
        HttpClient author = ManagementApiTests.Client(app, BowerRoles.Operator, "alice");
        await PrivacyProfileApiTests.RegisterActiveAsync(collector, admin, "edge-01", ct);
        PrivacyProfileVersionDetail version = await PrivacyProfileApiTests.SubmitAsync(
            author, PrivacyProfileApiTests.Profile("1.0.0"), ct);
        await PrivacyProfileApiTests.Review(admin, version.Id, "approve", "Reviewed", ct);
        using HttpResponseMessage assigned = await PrivacyProfileApiTests.Assign(admin, "edge-01", version.Id, "Roll out", ct);
        clock.Advance(PrivacyProfileDriftRecord.ConfirmationDelay);
        using HttpResponseMessage heartbeat = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat", PrivacyProfileApiTests.Heartbeat("default"), ct);

        using HttpResponseMessage response = await admin.GetAsync("/api/overview", ct);
        string body = await response.Content.ReadAsStringAsync(ct);
        OverviewRecord? overview = await admin.GetFromJsonAsync<OverviewRecord>(
            "/api/overview", ManagementApiTests.ApiJson, ct);

        Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, overview!.PrivacyProfileDrift);
        PrivacyProfileDriftRecord drift = Assert.Single(overview.PrivacyProfileExceptions!);
        Assert.Equal(version.ContentHash, drift.AssignedHash);
        Assert.Contains("\"privacyProfileExceptions\":[{\"collectorId\":\"edge-01\"", body, StringComparison.Ordinal);
        Assert.Contains("\"mismatchConfirmed\":true", body, StringComparison.Ordinal);
        // Hashes and identifiers only: no profile document, rule or key material.
        Assert.DoesNotContain("apiVersion", body, StringComparison.Ordinal);
        Assert.DoesNotContain("actor.username", body, StringComparison.Ordinal);
        Assert.DoesNotContain("id.email", body, StringComparison.Ordinal);
        Assert.DoesNotContain("hmac", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Contoso application telemetry", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Coverage_FreshActiveCollectorWithHealthySourcesIsReporting()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct);

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now - StaleAfter, ct);

        Assert.Equal((2, 1, 0), (overview.SourcesReporting, overview.SourcesDegraded, overview.SourcesUnknown));
    }

    [Fact]
    public async Task Coverage_StaleHeartbeatStopsReportingWithoutMaintenanceAndKeepsTheDenominator()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct);
        await ActiveAsync(store, "edge-02", TestEvents.Now.AddMinutes(10), ct);
        DateTimeOffset now = TestEvents.Now.AddMinutes(20);

        // edge-01 is past the threshold; the staleness job has not run.
        OverviewRecord unmaintained = await store.OverviewAsync(now - StaleAfter, ct);
        int marked = await store.MarkStaleAsync(now - StaleAfter, now, ct);
        OverviewRecord maintained = await store.OverviewAsync(now - StaleAfter, ct);

        Assert.Equal((2, 4, 3), (unmaintained.SourcesReporting, unmaintained.SourcesDegraded, unmaintained.SourcesUnknown));
        Assert.Equal(6, unmaintained.SourcesReporting + unmaintained.SourcesDegraded);
        Assert.Equal(1, marked);
        Assert.Equal(
            (unmaintained.SourcesReporting, unmaintained.SourcesDegraded, unmaintained.SourcesUnknown),
            (maintained.SourcesReporting, maintained.SourcesDegraded, maintained.SourcesUnknown));
    }

    [Fact]
    public async Task Coverage_PendingSourcesOnAFreshCollectorAreUnknownAndOverdueOnesDegraded()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        SourceReport[] sources =
        [
            new("http", "local-http", "healthy", 0, null),
            new("new-app", "application", "pending", null, null),
            new("new-api", "application", "Pending", null, null),
            new("old-app", "application", "never-seen", null, null),
            new("quiet-app", "application", "silent", 330, null)
        ];
        await store.RegisterAsync(Registration("edge-01") with { Sources = sources }, "principal", TestEvents.Now, ct);
        await store.DecideAsync("edge-01", CollectorStatus.Approved, "approved", "Expected", "admin", "Admin", TestEvents.Now, ct);
        await store.HeartbeatAsync("edge-01", Heartbeat() with { Sources = sources }, "principal", TestEvents.Now, ct);

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now - StaleAfter, ct);

        // pending has no evidence yet (unknown); never-seen and silent are overdue (degraded).
        // Unknown stays part of degraded, so reporting + degraded is all five sources.
        Assert.Equal((1, 4, 2), (overview.SourcesReporting, overview.SourcesDegraded, overview.SourcesUnknown));
    }

    [Theory]
    [InlineData("suspended", CollectorStatus.Suspended)]
    [InlineData("revoked", CollectorStatus.Revoked)]
    public async Task Coverage_SuspendedOrRevokedCollectorIsNotReportingDespiteHealthyRows(
        string action, CollectorStatus status)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await ActiveAsync(store, "edge-01", TestEvents.Now, ct);
        await store.DecideAsync("edge-01", status, action, "Lifecycle", "admin", "Admin", TestEvents.Now, ct);

        // The heartbeat is still fresh and the persisted source rows are still healthy.
        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now - StaleAfter, ct);

        Assert.Equal((0, 3, 3), (overview.SourcesReporting, overview.SourcesDegraded, overview.SourcesUnknown));
    }

    [Fact]
    public async Task Coverage_PendingRegistrationSourcesAreNotReporting()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = await StoreAsync(root, ct);
        await store.RegisterAsync(Registration("edge-01"), "principal", TestEvents.Now, ct);

        OverviewRecord overview = await store.OverviewAsync(TestEvents.Now - StaleAfter, ct);

        Assert.Equal((0, 3, 3), (overview.SourcesReporting, overview.SourcesDegraded, overview.SourcesUnknown));
    }

    [Fact]
    public async Task Coverage_ApiUsesTheClockAtQueryTimeAndAFreshHeartbeatRestoresReporting()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, ct);
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);
        await collector.PostAsJsonAsync("/api/collectors/register", Registration("edge-01"), ct);
        await admin.PostAsJsonAsync("/api/approvals/edge-01/approve", new ApprovalRequest("Expected"), ct);
        await HeartbeatAsync(collector, ct);

        OverviewRecord fresh = await OverviewAsync(admin, ct);
        clock.Advance(StaleAfter + TimeSpan.FromMinutes(1));
        OverviewRecord stale = await OverviewAsync(admin, ct);
        await app.Services.GetRequiredService<ManagementStore>().MarkStaleAsync(
            clock.GetUtcNow() - StaleAfter, clock.GetUtcNow(), ct);
        OverviewRecord maintained = await OverviewAsync(admin, ct);
        await HeartbeatAsync(collector, ct);
        OverviewRecord restored = await OverviewAsync(admin, ct);
        await admin.PostAsJsonAsync("/api/collectors/edge-01/suspend", new ApprovalRequest("Maintenance"), ct);
        OverviewRecord suspended = await OverviewAsync(admin, ct);
        using HttpResponseMessage refused = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat", Heartbeat(), ct);
        OverviewRecord stillSuspended = await OverviewAsync(admin, ct);
        await admin.PostAsJsonAsync("/api/collectors/edge-01/reinstate", new ApprovalRequest("Back"), ct);
        await HeartbeatAsync(collector, ct);
        OverviewRecord reinstated = await OverviewAsync(admin, ct);

        Assert.Equal((2, 1, 0), Coverage(fresh));
        Assert.Equal((0, 3, 3), Coverage(stale));
        Assert.Equal(1, stale.StaleCollectors);
        Assert.Equal(Coverage(stale), Coverage(maintained));
        Assert.Equal((2, 1, 0), Coverage(restored));
        Assert.Equal((0, 3, 3), Coverage(suspended));
        Assert.NotEqual(HttpStatusCode.OK, refused.StatusCode);
        Assert.Equal((0, 3, 3), Coverage(stillSuspended));
        Assert.Equal((2, 1, 0), Coverage(reinstated));
    }

    private static (int Reporting, int Degraded, int Unknown) Coverage(OverviewRecord overview) =>
        (overview.SourcesReporting, overview.SourcesDegraded, overview.SourcesUnknown);

    private static async Task<OverviewRecord> OverviewAsync(HttpClient client, CancellationToken ct) =>
        (await client.GetFromJsonAsync<OverviewRecord>("/api/overview", ManagementApiTests.ApiJson, ct))!;

    private static async Task HeartbeatAsync(HttpClient collector, CancellationToken ct)
    {
        using HttpResponseMessage response = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat", Heartbeat(), ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<ManagementStore> StoreAsync(TemporaryDirectory root, CancellationToken ct)
    {
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        await store.InitializeAsync(ct);
        return store;
    }

    /// <summary>Registers, approves and heartbeats a collector: two healthy sources, one lagging.</summary>
    private static async Task ActiveAsync(
        ManagementStore store, string id, DateTimeOffset at, CancellationToken ct, string? privacyProfileHash = null)
    {
        await store.RegisterAsync(Registration(id), "principal", at, ct);
        await store.DecideAsync(id, CollectorStatus.Approved, "approved", "Expected", "admin", "Admin", at, ct);
        await store.HeartbeatAsync(id, Heartbeat(privacyProfileHash), "principal", at, ct);
    }

    private static CollectorRegistration Registration(string id) =>
        new(id, id, "test", "0.1.0", "c", "p", Sources, []);

    private static CollectorHeartbeat Heartbeat(string? privacyProfileHash = null) =>
        new("0.1.0", "c", "p", 0, "healthy", Sources, [], PrivacyProfileHash: privacyProfileHash);

    private static readonly SourceReport[] Sources =
    [
        new("http", "local-http", "healthy", 0, null),
        new("sql", "sql-server", "healthy", 0, null),
        new("file", "file", "lagging", 900, null)
    ];

    private static async Task<PrivacyProfileVersionDetail> ApprovedVersionAsync(ManagementStore store, CancellationToken ct)
    {
        PrivacyProfileVersionDetail submitted = await store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("1.0.0")).Candidate,
            "Initial", "alice", "Alice", TestEvents.Now, ct);
        return (await store.ReviewPrivacyProfileVersionAsync(
            submitted.Id, true, "Reviewed", "bob", "Bob", TestEvents.Now, ct))!;
    }
}
