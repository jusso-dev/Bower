using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Bower.Evidence;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Plain-English home view: RBAC, traffic lights, fixes, proof wording and redaction counts.</summary>
[Collection(SerialHostTests.Name)]
public sealed class HomeApiTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 9, 30, 0, TimeSpan.Zero);
    private static readonly string[] FixPages =
        ["/setup", "/collectors", "/approvals", "/privacy-profiles", "/audit"];

    [Theory]
    [InlineData("")]
    [InlineData(BowerRoles.Collector)]
    public async Task Home_RequiresInteractiveRole(string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles)
            .GetAsync("/api/home", cancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Home_EmptyTenantPointsToSetupAndClaimsNoDelivery()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);

        HomeRecord home = await HomeAsync(app, cancellationToken);

        Assert.Equal(HomeStates.Amber, home.State);
        Assert.Equal("Not yet. No collectors are connected.", home.Flow.Summary);
        Assert.Equal(HomeProofStates.NotProven, home.Flow.Proof.State);
        Assert.Null(home.Flow.LastAcceptedAt);
        Assert.Equal(["no-collectors", HomeProofStates.NotProven], home.Attention.Select(item => item.Id));
        Assert.All(home.Attention, item => Assert.Equal("/setup", item.Fix.Page));
        Assert.Empty(home.Groups);
        Assert.Empty(home.Protection.ByType);
        Assert.Equal("No collector has reported privacy counts yet.", home.Protection.Summary);
        Assert.Equal(new DateTimeOffset(2026, 10, 21, 0, 0, 0, TimeSpan.Zero), home.Protection.Since);
    }

    [Fact]
    public async Task Home_GroupsByEnvironmentWorstFirstAndEveryReasonHasAFix()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "prod-01", "production", Now, Heartbeat(), cancellationToken);
        await ActiveAsync(store, "prod-02", "production", Now.AddMinutes(-20), Heartbeat(), cancellationToken);
        await ActiveAsync(store, "stage-01", "staging", Now, Heartbeat(), cancellationToken);
        await ActiveAsync(store, "stage-02", "staging", Now, Heartbeat() with { DeadLettered = 2 }, cancellationToken);
        await ActiveAsync(store, "test-01", "test", Now, Heartbeat(), cancellationToken);
        await store.RegisterAsync(Registration("new-01", "test"), "principal-new-01", Now, cancellationToken);

        HomeRecord home = await HomeAsync(app, cancellationToken);

        Assert.Equal(HomeStates.Red, home.State);
        Assert.Equal(["production", "staging", "test"], home.Groups.Select(group => group.Name));
        HomeGroup production = home.Groups[0];
        Assert.Equal(HomeStates.Red, production.State);
        Assert.Equal("1 of 2 collectors has not checked in for more than 15 minutes.", production.Reason);
        Assert.Equal("/collectors", production.Fix!.Page);
        Assert.Equal(1, production.Healthy);
        HomeGroup staging = home.Groups[1];
        Assert.Equal(HomeStates.Amber, staging.State);
        Assert.Equal("1 of 2 collectors has events that could not be sent and were set aside.", staging.Reason);
        HomeGroup test = home.Groups[2];
        Assert.Equal(HomeStates.Amber, test.State);
        Assert.Equal("1 of 2 collectors has asked to join.", test.Reason);
        Assert.Equal("/approvals", test.Fix!.Page);
        Assert.Equal("Partly. 4 of 5 collectors are sending events; 1 needs a look.", home.Flow.Summary);
        Assert.Equal(4, home.Flow.Sending);
        Assert.Equal(5, home.Flow.Enrolled);
        Assert.Equal(
            ["offline", "pending", "set-aside", HomeProofStates.NotProven],
            home.Attention.Select(item => item.Id));
        Assert.All(home.Attention, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Fix.Action));
            Assert.Contains(item.Fix.Page, FixPages);
        });

        // Once every collector is healthy (and the new one approved), the groups are green.
        await store.DecideAsync("new-01", CollectorStatus.Revoked, "rejected", "Not ours", "admin", "Admin", Now, cancellationToken);
        await HeartbeatAsync(store, "prod-02", Now, Heartbeat(), cancellationToken);
        await HeartbeatAsync(store, "stage-02", Now, Heartbeat(), cancellationToken);
        HomeRecord healthy = await HomeAsync(app, cancellationToken);

        Assert.All(healthy.Groups, group =>
        {
            Assert.Equal(HomeStates.Green, group.State);
            Assert.Null(group.Fix);
        });
        Assert.Equal("All 2 collectors are checking in and sending events.", healthy.Groups[0].Reason);
        Assert.Equal("The collector is checking in and sending events.", healthy.Groups[2].Reason);
        Assert.Equal(HomeStates.Green, healthy.Flow.State);
        // Not proven in Sentinel, so the page still asks for a test event.
        Assert.Equal(HomeStates.Amber, healthy.State);
    }

    [Fact]
    public async Task Home_DeliveryFailingForFifteenMinutesIsRedAndShorterTroubleIsAmber()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "edge-01", "production", Now.AddMinutes(-16), Heartbeat() with { DeliveryStatus = "degraded" }, cancellationToken);
        await HeartbeatAsync(store, "edge-01", Now, Heartbeat() with { DeliveryStatus = "degraded" }, cancellationToken);
        await ActiveAsync(store, "edge-02", "staging", Now, Heartbeat() with { DeliveryStatus = "degraded" }, cancellationToken);

        HomeRecord home = await HomeAsync(app, cancellationToken);

        Assert.Equal("The collector has not been able to send events for more than 15 minutes.", home.Groups[0].Reason);
        Assert.Equal(HomeStates.Red, home.Groups[0].State);
        Assert.Equal("The collector has had trouble sending events.", home.Groups[1].Reason);
        Assert.Equal(HomeStates.Amber, home.Groups[1].State);
        Assert.Equal(HomeStates.Red, home.Flow.State);
        Assert.Equal("No. None of your 2 collectors are sending events right now.", home.Flow.Summary);
    }

    [Fact]
    public async Task Home_SentinelProofComesOnlyFromAVerifiedRun()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(
            store, "edge-01", "production", Now,
            Heartbeat() with { SchemaVersion = 2, HeartbeatIntervalSeconds = 60, LastSuccessfulDeliveryAt = Now.AddMinutes(-1) },
            cancellationToken);

        HomeRecord accepted = await HomeAsync(app, cancellationToken);
        await CanaryAsync(store, EvidenceModes.Simulated, ProbeOutcomes.AcceptedNotVerified, Now.AddMinutes(1), cancellationToken);
        HomeRecord simulated = await HomeAsync(app, cancellationToken);
        await CanaryAsync(store, EvidenceModes.Verified, ProbeOutcomes.Verified, Now.AddMinutes(2), cancellationToken);
        await CanaryAsync(store, EvidenceModes.Simulated, ProbeOutcomes.AcceptedNotVerified, Now.AddMinutes(3), cancellationToken);
        HomeRecord verified = await HomeAsync(app, cancellationToken);

        // Collector acceptance is reported, but never as Sentinel proof.
        Assert.Equal(Now.AddMinutes(-1), accepted.Flow.LastAcceptedAt);
        Assert.Equal(HomeProofStates.NotProven, accepted.Flow.Proof.State);
        Assert.Equal(HomeProofStates.Simulated, simulated.Flow.Proof.State);
        Assert.StartsWith("Simulated only", simulated.Flow.Proof.Message, StringComparison.Ordinal);
        Assert.Contains(simulated.Attention, item => item.Id == HomeProofStates.Simulated && item.Fix.Page == "/setup");
        Assert.Equal(HomeProofStates.Verified, verified.Flow.Proof.State);
        Assert.Equal(Now.AddMinutes(2), verified.Flow.Proof.At);
        Assert.DoesNotContain(verified.Attention, item => item.Id is HomeProofStates.Simulated or HomeProofStates.NotProven);
        Assert.Equal(HomeStates.Green, verified.State);
    }

    [Fact]
    public async Task Home_RedactionCountsAreWeeklyIncreasesByTypeOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        DateTimeOffset started = Now.AddHours(-2);
        await ActiveAsync(store, "edge-01", "production", Now.AddDays(-1), Redacting(started, ("au.tfn", 5), ("secret.aws", 2)), cancellationToken);
        await ActiveAsync(store, "edge-02", "production", Now, Heartbeat(), cancellationToken);
        // The same process again: only the increase counts, and a repeat adds nothing.
        CollectorHeartbeat later = Redacting(
            started, ("au.tfn", 12), ("id.phone.au", 1), ("id.phone.intl", 1), ("secret.aws", 2));
        await HeartbeatAsync(store, "edge-01", Now, later, cancellationToken);
        await HeartbeatAsync(store, "edge-01", Now, later, cancellationToken);
        // A restart counts from zero again.
        await HeartbeatAsync(store, "edge-01", Now, Redacting(Now, ("au.tfn", 3), ("custom.claim-number", 4)), cancellationToken);

        HomeRecord home = await HomeAsync(app, cancellationToken);

        Assert.Equal(
            [
                ("au.tfn", "Tax file numbers", 15L),
                ("custom", "Matches for your own privacy rules", 4L),
                ("secrets", "Passwords, keys and access tokens", 2L),
                ("phone", "Phone numbers", 2L)
            ],
            home.Protection.ByType.Select(item => (item.Type, item.Label, item.Events)));
        Assert.Equal(1, home.Protection.CollectorsReporting);
        Assert.Equal(1, home.Protection.CollectorsNotReporting);

        // Eight days on, last week's counts have left the window.
        clock.Advance(TimeSpan.FromDays(8));
        await HeartbeatAsync(store, "edge-01", clock.UtcNow, Redacting(Now, ("au.tfn", 3), ("custom.claim-number", 4)), cancellationToken);
        HomeRecord nextWeek = await HomeAsync(app, cancellationToken);

        Assert.Empty(nextWeek.Protection.ByType);
        Assert.Equal("No sensitive details were found in events this week.", nextWeek.Protection.Summary);
    }

    [Theory]
    [InlineData("AU TFN", 1L)]
    [InlineData("au.tfn:sub", 1L)]
    [InlineData("", 1L)]
    [InlineData("au.tfn", -1L)]
    public async Task Heartbeat_RejectsInvalidRedactionReport(string type, long events)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveAsync(store, "edge-01", "production", Now, Heartbeat(), cancellationToken);

        await Assert.ThrowsAsync<ArgumentException>(() => HeartbeatAsync(
            store, "edge-01", Now, Redacting(Now, (type, events)), cancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => HeartbeatAsync(
            store, "edge-01", Now, Redacting(Now, ("au.tfn", 1), ("au.tfn", 2)), cancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => HeartbeatAsync(
            store, "edge-01", Now,
            Redacting(Now, [.. Enumerable.Range(0, ManagementStore.MaximumRedactionTypes + 1).Select(index => ($"custom.type-{index}", 1L))]),
            cancellationToken));
    }

    [Fact]
    public async Task Home_LoadsUnderTwoSecondsForFiveHundredCollectors()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        SourceReport[] sources =
        [
            new("local-http", "local-http", "healthy", null, null),
            new("claims/production", "application", "healthy", 3, Now),
            new("hr/production", "application", "silent", 900, Now.AddMinutes(-15))
        ];
        for (int index = 0; index < 500; index++)
        {
            await ActiveAsync(
                store, $"edge-{index:D3}", $"site-{index % 20:D2}", Now.AddMinutes(-(index % 30)),
                Redacting(Now.AddHours(-1), ("au.tfn", index), ("id.email", 2)) with { Sources = sources },
                cancellationToken);
        }

        HttpClient viewer = ManagementApiTests.Client(app, BowerRoles.Viewer);
        await HomeAsync(app, cancellationToken);
        Stopwatch timer = Stopwatch.StartNew();
        HomeRecord home = await viewer.GetFromJsonAsync<HomeRecord>("/api/home", ManagementApiTests.ApiJson, cancellationToken)
            ?? throw new InvalidOperationException("No home view.");
        timer.Stop();

        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"Home view took {timer.Elapsed}.");
        Assert.Equal(20, home.Groups.Count);
        Assert.Equal(500, home.Groups.Sum(group => group.Collectors));
        Assert.Equal(124_750L, home.Protection.ByType.Single(item => item.Type == "au.tfn").Events);
    }

    private static async Task<HomeRecord> HomeAsync(WebApplication app, CancellationToken cancellationToken) =>
        await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<HomeRecord>("/api/home", ManagementApiTests.ApiJson, cancellationToken)
        ?? throw new InvalidOperationException("No home view.");

    private static CollectorRegistration Registration(string id, string environment) =>
        new(id, id, environment, "0.1.0", "c", "p", [new SourceReport("local-http", "local-http", "healthy", null, null)], []);

    private static CollectorHeartbeat Heartbeat() =>
        new("0.1.0", "c", "p", 0, "healthy", [new SourceReport("local-http", "local-http", "healthy", null, null)], []);

    private static CollectorHeartbeat Redacting(DateTimeOffset since, params (string Type, long Events)[] counts) =>
        Heartbeat() with
        {
            Redactions = new RedactionReport(since, [.. counts.Select(item => new RedactionReportCount(item.Type, item.Events))])
        };

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

    private static async Task CanaryAsync(
        ManagementStore store,
        string mode,
        string outcome,
        DateTimeOffset at,
        CancellationToken cancellationToken)
    {
        SetupCanaryRun run = await store.StartSetupCanaryRunAsync(
            ProbeProfiles.Generic, "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b", "BowerSecurity_CL", "admin", "Admin", at, cancellationToken);
        await store.CompleteSetupCanaryRunAsync(
            run.Id, new SetupCanaryResult(mode, outcome, true, "canary-event", 4.2, false, null), at, cancellationToken);
    }
}
