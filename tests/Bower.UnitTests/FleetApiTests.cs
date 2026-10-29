using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Plain-English fleet view: RBAC, one state and fix per collector, relay paths, versions and credentials.</summary>
[Collection(SerialHostTests.Name)]
public sealed class FleetApiTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 9, 30, 0, TimeSpan.Zero);
    private static readonly string[] FixPages = ["/approvals", "/audit", "/enrolment", "/privacy-profiles"];
    private static readonly string[] Lights = [HomeStates.Red, HomeStates.Amber, HomeStates.Green, FleetLights.None];

    [Theory]
    [InlineData("/api/fleet", "")]
    [InlineData("/api/fleet", BowerRoles.Collector)]
    [InlineData("/api/fleet/edge-01", "")]
    [InlineData("/api/fleet/edge-01", BowerRoles.Collector)]
    public async Task Fleet_RequiresInteractiveRole(string path, string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles).GetAsync(path, cancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Fleet_ViewerReadsAndCannotChangeAnything()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        HttpClient viewer = ManagementApiTests.Client(app, BowerRoles.Viewer);

        using HttpResponseMessage read = await viewer.GetAsync("/api/fleet", cancellationToken);
        using HttpResponseMessage post = await viewer.PostAsJsonAsync("/api/fleet", new { }, cancellationToken);
        using HttpResponseMessage missing = await viewer.GetAsync("/api/fleet/unknown", cancellationToken);

        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, post.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        FleetRecord? empty = await read.Content.ReadFromJsonAsync<FleetRecord>(ManagementApiTests.ApiJson, cancellationToken);
        Assert.Empty(empty!.Collectors);
        Assert.Empty(empty.States);
        Assert.Empty(empty.Sites);
        Assert.Null(empty.NewestVersion);
    }

    [Fact]
    public async Task Fleet_EveryCollectorShowsOnePlainStateAndFix()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "healthy-01", "production", Now, Heartbeat(), cancellationToken);
        await ActiveAsync(store, "relayed-01", "branch-office", Now, Heartbeat() with { Outputs = [RelayOutput()] }, cancellationToken);
        await store.RegisterAsync(Registration("pending-01", "production"), "principal-pending-01", Now, cancellationToken);
        await ActiveAsync(store, "stale-01", "production", Now.AddMinutes(-5), Heartbeat(), cancellationToken);
        await ActiveAsync(store, "offline-01", "branch-office", Now.AddMinutes(-20), Heartbeat(), cancellationToken);
        await ActiveAsync(store, "failing-01", "production", Now.AddMinutes(-16), Heartbeat() with { DeliveryStatus = "degraded" }, cancellationToken);
        await HeartbeatAsync(store, "failing-01", Now, Heartbeat() with { DeliveryStatus = "degraded" }, cancellationToken);
        await ActiveAsync(store, "relay-failing-01", "branch-office", Now, Heartbeat() with
        {
            DeliveryStatus = "degraded",
            Outputs = [RelayOutput()]
        }, cancellationToken);
        await ActiveAsync(store, "tampered-01", "production", Now, Heartbeat() with { DeliveryStatus = "ledger-regression" }, cancellationToken);
        await ActiveAsync(store, "quiet-01", "production", Now, Heartbeat() with
        {
            Sources = [new SourceReport("app/production", "application", "silent", 3600, Now.AddHours(-1))]
        }, cancellationToken);
        await ActiveAsync(store, "old-01", "production", Now, Heartbeat() with { Version = "0.0.9" }, cancellationToken);
        await ActiveAsync(store, "v1-01", "production", Now, Heartbeat() with { SchemaVersion = null }, cancellationToken);
        await ActiveAsync(store, "paused-01", "production", Now, Heartbeat(), cancellationToken);
        await store.DecideAsync("paused-01", CollectorStatus.Suspended, "suspended", "Investigating", "admin", "Admin", Now, cancellationToken);
        await ActiveAsync(store, "removed-01", "production", Now, Heartbeat(), cancellationToken);
        await store.DecideAsync("removed-01", CollectorStatus.Revoked, "revoked", "Decommissioned", "admin", "Admin", Now, cancellationToken);

        FleetRecord fleet = await FleetAsync(app, cancellationToken);
        Dictionary<string, FleetCollector> byId = fleet.Collectors.ToDictionary(item => item.Id);

        Assert.Equal(13, fleet.Collectors.Count);
        Assert.All(fleet.Collectors, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Label));
            Assert.False(string.IsNullOrWhiteSpace(item.Reason));
            Assert.Contains(item.Light, Lights);
            if (item.Light is HomeStates.Red or HomeStates.Amber)
            {
                Assert.NotNull(item.Fix);
                Assert.False(string.IsNullOrWhiteSpace(item.Fix!.Action));
                Assert.True(item.Fix.Page is null || FixPages.Contains(item.Fix.Page), item.Fix.Page);
            }
            else
            {
                Assert.Null(item.Fix);
            }
        });

        Expect(byId["healthy-01"], FleetStates.Healthy, "Healthy", HomeStates.Green);
        Assert.Equal(FleetPaths.Direct, byId["healthy-01"].Path);
        Expect(byId["relayed-01"], FleetStates.BehindRelay, "Behind a relay", HomeStates.Green);
        Assert.Equal(FleetPaths.Relay, byId["relayed-01"].Path);
        Expect(byId["pending-01"], FleetStates.WaitingForApproval, "Waiting for approval", HomeStates.Amber);
        Assert.Equal("/approvals", byId["pending-01"].Fix!.Page);
        Expect(byId["stale-01"], FleetStates.NotHeardFrom, "Not heard from recently", HomeStates.Amber);
        Expect(byId["offline-01"], FleetStates.NotHeardFrom, "Not heard from recently", HomeStates.Red);
        Assert.Equal("Has not checked in for more than 15 minutes.", byId["offline-01"].Reason);
        Assert.Null(byId["offline-01"].Fix!.Page);
        Expect(byId["failing-01"], FleetStates.CannotDeliver, "Can't deliver to Sentinel", HomeStates.Red);
        Assert.Equal("Check the machine's connection to Azure.", byId["failing-01"].Fix!.Action);
        Expect(byId["relay-failing-01"], FleetStates.CannotDeliver, "Can't deliver to Sentinel", HomeStates.Amber);
        Assert.Contains("its relay", byId["relay-failing-01"].Fix!.Action, StringComparison.Ordinal);
        Expect(byId["tampered-01"], FleetStates.NeedsCheck, "Needs a check", HomeStates.Red);
        Assert.Equal("/audit", byId["tampered-01"].Fix!.Page);
        Expect(byId["quiet-01"], FleetStates.NeedsCheck, "Needs a check", HomeStates.Amber);
        Expect(byId["old-01"], FleetStates.OldVersion, "Running old version", HomeStates.Amber);
        Assert.Equal("Runs an older Bower version than the newest one in your fleet.", byId["old-01"].Reason);
        Expect(byId["v1-01"], FleetStates.OldVersion, "Running old version", HomeStates.Amber);
        Assert.Contains("signed commands", byId["v1-01"].Reason, StringComparison.Ordinal);
        Expect(byId["paused-01"], FleetStates.Paused, "Paused", HomeStates.Amber);
        Expect(byId["removed-01"], FleetStates.Removed, "Removed", FleetLights.None);
        Assert.Equal("0.1.0", fleet.NewestVersion);

        // Most urgent first: red, then amber, then green, then removed.
        Assert.Equal(
            [.. fleet.Collectors.Select(item => Array.IndexOf(Lights, item.Light)).Order()],
            fleet.Collectors.Select(item => Array.IndexOf(Lights, item.Light)));
        Assert.Equal("removed-01", fleet.Collectors[^1].Id);
        Assert.Equal(
            [
                FleetStates.NotHeardFrom, FleetStates.CannotDeliver, FleetStates.NeedsCheck,
                FleetStates.WaitingForApproval, FleetStates.Paused, FleetStates.OldVersion,
                FleetStates.BehindRelay, FleetStates.Healthy, FleetStates.Removed
            ],
            fleet.States.Select(item => item.State));
        Assert.Equal(13, fleet.States.Sum(item => item.Collectors));
        Assert.Equal(HomeStates.Red, fleet.States[0].Light);
        Assert.Equal(
            [new FleetSiteCount("branch-office", 3), new FleetSiteCount("production", 10)],
            fleet.Sites);

        FleetCollector? single = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<FleetCollector>("/api/fleet/offline-01", ManagementApiTests.ApiJson, cancellationToken);
        Assert.Equal(byId["offline-01"], single);
    }

    [Fact]
    public async Task Fleet_AgreesWithTheHomeView()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "prod-01", "production", Now, Heartbeat(), cancellationToken);
        await ActiveAsync(store, "prod-02", "production", Now.AddMinutes(-20), Heartbeat(), cancellationToken);
        await ActiveAsync(store, "stage-01", "staging", Now, Heartbeat() with { DeadLettered = 2 }, cancellationToken);
        await ActiveAsync(store, "stage-02", "staging", Now, Heartbeat() with { OldestUndeliveredAgeSeconds = 3600 }, cancellationToken);

        HomeRecord home = (await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<HomeRecord>("/api/home", ManagementApiTests.ApiJson, cancellationToken))!;
        FleetRecord fleet = await FleetAsync(app, cancellationToken);

        foreach (HomeGroup group in home.Groups)
        {
            FleetCollector[] members = [.. fleet.Collectors.Where(item => item.Site == group.Name)];
            Assert.Equal(group.Collectors, members.Length);
            Assert.Equal(group.Healthy, members.Count(item => item.Light == HomeStates.Green));
            Assert.Equal(group.State, members.Select(item => item.Light).OrderBy(light => Array.IndexOf(Lights, light)).First());
        }

        FleetCollector stage = fleet.Collectors.Single(item => item.Id == "stage-01");
        Assert.Equal(FleetStates.CannotDeliver, stage.State);
        Assert.Equal("Has events that could not be sent and were set aside.", stage.Reason);
        Assert.Equal(FleetStates.CannotDeliver, fleet.Collectors.Single(item => item.Id == "stage-02").State);
    }

    [Fact]
    public async Task Fleet_CountsFurtherIssuesTheReasonDoesNotMention()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "new-01", "production", Now, Heartbeat() with { Version = "0.2.0" }, cancellationToken);
        await ActiveAsync(store, "busy-01", "production", Now, Heartbeat() with
        {
            Version = "0.1.0",
            DeliveryStatus = "degraded",
            DeadLettered = 4
        }, cancellationToken);

        FleetCollector busy = (await FleetAsync(app, cancellationToken)).Collectors.Single(item => item.Id == "busy-01");

        Assert.Equal(FleetStates.CannotDeliver, busy.State);
        Assert.Equal("Has had trouble sending events.", busy.Reason);
        // Set aside and an older version are further issues.
        Assert.Equal(2, busy.OtherIssues);
    }

    [Fact]
    public async Task Fleet_RevokedCredentialPointsToEnrolment()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        DateTimeOffset enrolled = Now.AddMinutes(-30);
        IssuedEnrolmentToken token = await store.CreateEnrolmentTokenAsync(
            new EnrolmentTokenRequest("branch-office", "Branch office collector"), "admin", "Admin", enrolled, cancellationToken);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string publicKey = key.ExportSubjectPublicKeyInfoPem();
        Assert.True(CollectorEnrolment.TryReadPublicKey(publicKey, out string normalised, out string credentialId));
        EnrolmentResult result = await store.EnrolAsync(
            new CollectorEnrolmentRequest(token.Token, "edge-01", "edge-01", "branch-office", "0.1.0", "c", "p", publicKey),
            normalised, credentialId, enrolled, cancellationToken);
        Assert.Null(result.Refusal);
        await store.DecideAsync("edge-01", CollectorStatus.Approved, "approved", "Expected collector", "admin", "Admin", enrolled, cancellationToken);
        await store.ExchangeHeartbeatAsync(
            "edge-01", Heartbeat(), CollectorEnrolment.PrincipalFor("edge-01"), enrolled, cancellationToken);

        FleetCollector before = (await FleetAsync(app, cancellationToken)).Collectors.Single();
        Assert.Equal(FleetStates.NotHeardFrom, before.State);
        Assert.Null(before.Fix!.Page);

        Assert.NotNull(await store.RevokeCredentialAsync(
            "edge-01", credentialId, "Lost laptop", "admin", "Admin", enrolled.AddMinutes(1), cancellationToken));
        FleetCollector after = (await FleetAsync(app, cancellationToken)).Collectors.Single();

        Assert.Equal(FleetStates.NotHeardFrom, after.State);
        Assert.Equal(HomeStates.Red, after.Light);
        Assert.Contains("credential was revoked or has expired", after.Reason, StringComparison.Ordinal);
        Assert.Equal("/enrolment", after.Fix!.Page);
    }

    [Fact]
    public async Task Fleet_NeverEchoesCollectorReportedText()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        const string Hostile = "<img src=x onerror=alert(1)> password=hunter2";
        await ActiveAsync(store, "edge-01", "production", Now, Heartbeat() with
        {
            DeliveryStatus = Hostile,
            Version = "9.9.9",
            Outputs = [new OutputReport("relay", "relay", Hostile, null, Hostile)]
        }, cancellationToken);

        FleetCollector item = (await FleetAsync(app, cancellationToken)).Collectors.Single();

        Assert.DoesNotContain("hunter2", item.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", item.Fix!.Action, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", item.Label, StringComparison.Ordinal);
        Assert.Equal(FleetStates.CannotDeliver, item.State);
    }

    [Theory]
    [InlineData("0.1.0", "0.2.0", true)]
    [InlineData("1.10.0", "1.9.9", false)]
    [InlineData("2.0.0-rc.1", "2.0.0", true)]
    [InlineData("2.0.0-rc.1", "2.0.0-rc.2", false)]
    [InlineData("2.0.0+build.5", "2.0.0", false)]
    public void Fleet_ComparesVersionNumbersAndStableReleases(string installed, string other, bool outdated)
    {
        FleetRecord fleet = FleetStatus.Evaluate([Record("installed", installed), Record("other", other)], new HashSet<string>(), Now);
        Assert.Equal(outdated ? FleetStates.OldVersion : FleetStates.Healthy,
            fleet.Collectors.Single(item => item.Id == "installed").State);
    }

    [Theory]
    [InlineData("")]
    [InlineData("dev")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.x")]
    [InlineData("1.2.3-")]
    [InlineData("-1.2.3")]
    [InlineData("99999999999.0.0")]
    [InlineData("01.2.3")]
    [InlineData("1.2.3+")]
    [InlineData("1.2.3+meta+extra")]
    [InlineData("1.2.3-rc..1")]
    [InlineData("1.2.3-01")]
    [InlineData("1.2.3-<script>")]
    public void Fleet_DoesNotCompareMalformedVersions(string value)
    {
        FleetRecord fleet = FleetStatus.Evaluate([Record("unknown", value), Record("known", "1.0.0")], new HashSet<string>(), Now);
        Assert.Equal("1.0.0", fleet.NewestVersion);
        Assert.All(fleet.Collectors, item => Assert.Equal(FleetStates.Healthy, item.State));
    }

    private static CollectorRecord Record(string id, string version) =>
        new(id, id, "production", version, CollectorStatus.Active, "principal", Now, Now,
            "c", "p", 0, "healthy", [], [], HeartbeatSchemaVersion: 2, HeartbeatIntervalSeconds: 60);

    [Fact]
    public async Task Fleet_UnparseableVersionsAreNeverOld()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "dev-01", "production", Now, Heartbeat() with { Version = "dev-build" }, cancellationToken);
        await ActiveAsync(store, "rel-01", "production", Now, Heartbeat() with { Version = "1.0.0" }, cancellationToken);

        FleetRecord fleet = await FleetAsync(app, cancellationToken);

        Assert.All(fleet.Collectors, item => Assert.Equal(FleetStates.Healthy, item.State));
        Assert.Equal("1.0.0", fleet.NewestVersion);
    }

    [Fact]
    public async Task Fleet_StaleAndPreviewReleasesDoNotMakeStableCollectorsOld()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "stable", "production", Now, Heartbeat(), cancellationToken);
        await ActiveAsync(store, "preview", "test", Now, Heartbeat() with { Version = "9.0.0-rc.1" }, cancellationToken);
        await ActiveAsync(store, "retired", "test", Now.AddDays(-1), Heartbeat() with { Version = "8.0.0" }, cancellationToken);

        FleetRecord fleet = await FleetAsync(app, cancellationToken);

        Assert.Equal("0.1.0", fleet.NewestVersion);
        Assert.Equal(FleetStates.Healthy, fleet.Collectors.Single(item => item.Id == "stable").State);
        Assert.DoesNotContain("sending events", fleet.Collectors.Single(item => item.Id == "stable").Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Fleet_FiveHundredCollectorsStayFast()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        for (int index = 0; index < 500; index++)
        {
            await ActiveAsync(store, $"edge-{index:D3}", $"site-{index % 20:D2}", Now, Heartbeat(), cancellationToken);
        }

        Stopwatch timer = Stopwatch.StartNew();
        FleetRecord fleet = await FleetAsync(app, cancellationToken);
        timer.Stop();

        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"Fleet view took {timer.Elapsed}.");
        Assert.Equal(500, fleet.Collectors.Count);
        Assert.Equal(20, fleet.Sites.Count);
    }

    private static void Expect(FleetCollector item, string state, string label, string light)
    {
        Assert.Equal(state, item.State);
        Assert.Equal(label, item.Label);
        Assert.Equal(light, item.Light);
    }

    private static async Task<FleetRecord> FleetAsync(WebApplication app, CancellationToken cancellationToken) =>
        await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<FleetRecord>("/api/fleet", ManagementApiTests.ApiJson, cancellationToken)
        ?? throw new InvalidOperationException("No fleet view.");

    private static OutputReport RelayOutput() => new("relay", "relay", "healthy", null, null);

    private static CollectorRegistration Registration(string id, string environment) =>
        new(id, id, environment, "0.1.0", "c", "p", [new SourceReport("local-http", "local-http", "healthy", null, null)], []);

    private static CollectorHeartbeat Heartbeat() =>
        new(
            "0.1.0", "c", "p", 0, "healthy",
            [new SourceReport("local-http", "local-http", "healthy", null, null)],
            [new OutputReport("azure-logs-ingestion", "azure-logs-ingestion", "healthy", null, null)],
            SchemaVersion: 2,
            HeartbeatIntervalSeconds: 60);

    private static async Task ActiveAsync(
        ManagementStore store,
        string id,
        string environment,
        DateTimeOffset seen,
        CollectorHeartbeat heartbeat,
        CancellationToken cancellationToken)
    {
        await store.RegisterAsync(Registration(id, environment), $"principal-{id}", seen, cancellationToken);
        await store.DecideAsync(id, CollectorStatus.Approved, "approved", "Expected collector", "admin", "Admin", seen, cancellationToken);
        await HeartbeatAsync(store, id, seen, heartbeat, cancellationToken);
    }

    private static Task<HeartbeatExchange?> HeartbeatAsync(
        ManagementStore store,
        string id,
        DateTimeOffset now,
        CollectorHeartbeat heartbeat,
        CancellationToken cancellationToken) =>
        store.ExchangeHeartbeatAsync(id, heartbeat, $"principal-{id}", now, cancellationToken);
}
