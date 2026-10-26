using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Integrity;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using CollectorVerifier = Bower.Collector.ManagementCommandVerifier;

namespace Bower.UnitTests;

/// <summary>Heartbeat v2 on the management API: compatibility, commands, audit and connectivity.</summary>
[Collection(SerialHostTests.Name)]
public sealed class HeartbeatV2ManagementTests
{
    private const string CollectorId = "edge-v2";
    private static readonly DateTimeOffset Start = new(2026, 10, 26, 0, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = ManagementApiTests.ApiJson;

    [Fact]
    public async Task V1Heartbeat_StillReceivesTheCollectorRecordAndNeverCommands()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);

        // A v2 heartbeat advertises run-canary, then the collector is downgraded to v1.
        await HeartbeatV2Async(collector, ct, capabilities: ["run-canary"]);
        using HttpResponseMessage v1 = await collector.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/heartbeat",
            new CollectorHeartbeat("0.1.0", "c", "p", 0, "healthy", [], []),
            ct);
        string body = await v1.Content.ReadAsStringAsync(ct);
        using HttpResponseMessage issue = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "probe"), ct);
        CollectorRecord? record = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct);

        Assert.Equal(HttpStatusCode.OK, v1.StatusCode);
        Assert.Contains($"\"id\":\"{CollectorId}\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"commands\"", body, StringComparison.Ordinal);
        Assert.Equal(1, record!.HeartbeatSchemaVersion);
        Assert.Empty(record.CommandCapabilities!);
        // A v1 collector advertises nothing, so nothing can be issued to it.
        Assert.Equal(HttpStatusCode.Conflict, issue.StatusCode);
    }

    [Fact]
    public async Task V2Heartbeat_StoresRicherMetadataAndReturnsTheV2Response()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);
        string canaryCommand = new('a', 32);

        HeartbeatResponse response = await HeartbeatV2Async(
            collector,
            ct,
            capabilities: ["run-canary", "reload", "not-a-command"],
            canary: new CanaryReport(canaryCommand, "bower-canary-1", Start, "queued"),
            sources:
            [
                new SourceReport("local-http", "local-http", "healthy", null, null),
                new SourceReport("payments/prod", "application", "pending", null, null),
                new SourceReport("orders/prod", "application", "silent", 900, Start)
            ]);
        CollectorRecord? record = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct);

        Assert.Equal(2, response.SchemaVersion);
        Assert.Equal(CollectorId, response.CollectorId);
        Assert.Empty(response.Commands);
        Assert.Equal(2, record!.HeartbeatSchemaVersion);
        Assert.Equal(60, record.HeartbeatIntervalSeconds);
        Assert.Equal(42, record.OldestUndeliveredAgeSeconds);
        Assert.Equal(Start.AddSeconds(-30), record.LastSuccessfulDeliveryAt);
        Assert.Equal("queued", record.LastCanary!.Outcome);
        // Unknown capabilities are never stored, so they can never be issued.
        Assert.Equal(["run-canary", "reload"], record.CommandCapabilities);
        // #81's pending sources stay their own bucket: neither healthy nor degraded.
        Assert.Equal(new SourceHealthSummary(3, 1, 1, 1), record.SourceSummary);
        Assert.Equal(CollectorConnectivity.Online, record.Connectivity);
    }

    [Fact]
    public async Task Commands_AreAuthorisedByTypeSignedDeliveredAndAcknowledged()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out string publicPem);
        HttpClient collector = await EnrolAsync(app, ct);
        HttpClient operatorClient = Client(app, BowerRoles.Operator);
        HttpClient administrator = Client(app, BowerRoles.Administrator);
        await HeartbeatV2Async(collector, ct, capabilities: ["run-canary", "reload"]);

        using HttpResponseMessage canary = await operatorClient.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "Check the pipeline"), ct);
        using HttpResponseMessage reloadAsOperator = await operatorClient.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("reload", "Restart"), ct);
        using HttpResponseMessage reload = await administrator.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("reload", "Restart", 5), ct);
        using HttpResponseMessage unknown = await administrator.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("exec", "rm -rf /"), ct);
        using HttpResponseMessage notAdvertised = await administrator.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("rotate-credential", "Rotate"), ct);
        using HttpResponseMessage tooLong = await administrator.PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "x", 61), ct);
        using HttpResponseMessage asViewer = await Client(app, BowerRoles.Viewer).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "x"), ct);

        Assert.Equal(HttpStatusCode.Accepted, canary.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, reloadAsOperator.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, reload.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, notAdvertised.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, asViewer.StatusCode);
        CollectorCommandRecord issued = (await canary.Content.ReadFromJsonAsync<CollectorCommandRecord>(Json, ct))!;

        // Delivered on the next heartbeat, verifiable by the collector's own verifier.
        clock.Advance(TimeSpan.FromMinutes(1));
        HeartbeatResponse first = await HeartbeatV2Async(collector, ct, capabilities: ["run-canary", "reload"]);
        HeartbeatResponse again = await HeartbeatV2Async(collector, ct, capabilities: ["run-canary", "reload"]);
        Assert.Equal(2, first.Commands.Count);
        foreach (SignedCollectorCommand command in first.Commands)
        {
            JsonElement element = JsonSerializer.SerializeToElement(command, Json);
            Bower.Collector.ManagementCommandVerification verified = CollectorVerifier.Verify(
                element, CollectorId, [publicPem], clock.GetUtcNow());
            Assert.Null(verified.RejectionCode);
            Assert.Equal(command.Command, verified.Command!.Command);
        }

        // Redelivered byte for byte until a result arrives.
        Assert.Equal(
            JsonSerializer.Serialize(first.Commands, Json),
            JsonSerializer.Serialize(again.Commands, Json));
        SignedCollectorCommand delivered = first.Commands.Single(item => item.CommandId == issued.Id);
        Assert.Equal(32, delivered.Nonce.Length);

        HeartbeatResponse reported = await HeartbeatV2Async(
            collector,
            ct,
            capabilities: ["run-canary", "reload"],
            results:
            [
                new CommandResultReport(issued.Id, "succeeded", "canary-queued", clock.GetUtcNow()),
                new CommandResultReport(new string('f', 32), "rejected", "untrusted-signature", clock.GetUtcNow()),
                new CommandResultReport(null, "rejected", "malformed-command", clock.GetUtcNow())
            ]);
        IReadOnlyList<CollectorCommandRecord>? commands = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<List<CollectorCommandRecord>>($"/api/collectors/{CollectorId}/commands", Json, ct);
        AuditRecord[]? audit = await administrator.GetFromJsonAsync<AuditRecord[]>("/api/audit", ct);

        Assert.Equal([issued.Id, new string('f', 32)], reported.AcknowledgedResults);
        Assert.DoesNotContain(reported.Commands, item => item.CommandId == issued.Id);
        CollectorCommandRecord done = commands!.Single(item => item.Id == issued.Id);
        Assert.Equal("succeeded", done.Status);
        Assert.Equal("canary-queued", done.ResultCode);
        Assert.Contains(audit!, item => item.Action == "collector.command-issued:run-canary"
            && item.TargetType == "collector-command" && item.TargetId == $"{CollectorId}/{issued.Id}");
        Assert.Contains(audit!, item => item.Action == "collector.command-delivered");
        Assert.Contains(audit!, item => item.Action == "collector.command-succeeded");
        Assert.Contains(audit!, item => item.Action == "collector.command-refused" && item.TargetId == CollectorId);
        Assert.Single(audit!, item => item.Action == "collector.command-result-unknown");
    }

    [Fact]
    public async Task Commands_ExpireWithoutAResultAndAreAudited()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);
        await HeartbeatV2Async(collector, ct, capabilities: ["run-canary"]);
        using HttpResponseMessage issued = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "probe", 1), ct);

        clock.Advance(TimeSpan.FromMinutes(2));
        HeartbeatResponse response = await HeartbeatV2Async(collector, ct, capabilities: ["run-canary"]);
        List<CollectorCommandRecord>? commands = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<List<CollectorCommandRecord>>($"/api/collectors/{CollectorId}/commands", Json, ct);
        AuditRecord[]? audit = await Client(app, BowerRoles.Viewer).GetFromJsonAsync<AuditRecord[]>("/api/audit", ct);

        Assert.Equal(HttpStatusCode.Accepted, issued.StatusCode);
        Assert.Empty(response.Commands);
        Assert.Equal("expired", Assert.Single(commands!).Status);
        Assert.Contains(audit!, item => item.Action == "collector.command-expired");
    }

    [Fact]
    public async Task Commands_ExpireForOfflineSuspendedAndV1CollectorsWithoutAHeartbeatExchange()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out _);
        string[] collectors = ["edge-offline", "edge-suspended", "edge-v1"];
        Dictionary<string, HttpClient> clients = [];
        foreach (string id in collectors)
        {
            clients[id] = await EnrolAsync(app, ct, id);
            await HeartbeatV2Async(clients[id], ct, capabilities: ["run-canary"], collectorId: id);
            using HttpResponseMessage issued = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
                $"/api/collectors/{id}/commands", new CollectorCommandRequest("run-canary", "probe", 1), ct);
            Assert.Equal(HttpStatusCode.Accepted, issued.StatusCode);
        }

        using HttpResponseMessage suspended = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            "/api/collectors/edge-suspended/suspend", new ApprovalRequest("maintenance"), ct);
        Assert.Equal(HttpStatusCode.OK, suspended.StatusCode);
        clock.Advance(TimeSpan.FromMinutes(2));
        // Downgraded: v1 heartbeats keep it active but never run the v2 command exchange.
        using HttpResponseMessage v1 = await clients["edge-v1"].PostAsJsonAsync(
            "/api/collectors/edge-v1/heartbeat", new CollectorHeartbeat("0.1.0", "c", "p", 0, "healthy", [], []), ct);
        Assert.Equal(HttpStatusCode.OK, v1.StatusCode);

        // Read time: an overdue command is never shown as live, even before any job runs.
        foreach (string id in collectors)
        {
            List<CollectorCommandRecord>? listed = await Client(app, BowerRoles.Viewer)
                .GetFromJsonAsync<List<CollectorCommandRecord>>($"/api/collectors/{id}/commands", Json, ct);
            Assert.Equal(CollectorCommandStatus.Expired, Assert.Single(listed!).Status);
        }

        Assert.DoesNotContain(await AuditAsync(app, ct), item => item.Action == "collector.command-expired");

        // The staleness maintenance job expires and audits them once.
        Bower.Management.Api.Jobs.CollectorStalenessJob job = new(
            app.Services.GetRequiredService<ManagementStore>(), clock,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<Bower.Management.Api.Jobs.CollectorStalenessJob>.Instance);
        await job.RunAsync(ct);
        await job.RunAsync(ct);
        AuditRecord[] audit = await AuditAsync(app, ct);

        Assert.Equal(3, audit.Count(item => item.Action == "collector.command-expired"));
        foreach (string id in collectors)
        {
            Assert.Single(audit, item => item.Action == "collector.command-expired"
                && item.TargetId.StartsWith($"{id}/", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Commands_RefusedForRoleAreAudited()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, new FakeClock(Start), ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);
        await HeartbeatV2Async(collector, ct, capabilities: ["reload"]);

        using HttpResponseMessage reload = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("reload", "Restart"), ct);
        AuditRecord[] audit = await AuditAsync(app, ct);

        Assert.Equal(HttpStatusCode.Forbidden, reload.StatusCode);
        AuditRecord refused = Assert.Single(audit, item => item.Action == "collector.command-forbidden:reload");
        Assert.Equal(CollectorId, refused.TargetId);
        Assert.Equal($"principal-{BowerRoles.Operator}", refused.ActorObjectId);
    }

    [Fact]
    public async Task Commands_WithoutASigningKeyAre503AndEverythingElseWorks()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Start), ct);
        HttpClient collector = await EnrolAsync(app, ct);
        HeartbeatResponse response = await HeartbeatV2Async(collector, ct, capabilities: ["run-canary"]);

        using HttpResponseMessage issue = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/commands", new CollectorCommandRequest("run-canary", "probe"), ct);

        Assert.Equal(2, response.SchemaVersion);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, issue.StatusCode);
    }

    [Fact]
    public void Signer_CanonicalBytesMatchTheCollectorVerifier()
    {
        byte[] management = ManagementCommandSigner.SignedBytes(
            new string('1', 32), "edge-é<&>", "run-canary", new string('2', 32),
            "2026-10-26T00:00:00.0000000Z", "2026-10-26T00:15:00.0000000Z");
        byte[] collector = CollectorVerifier.SignedBytes(
            new string('1', 32), "edge-é<&>", "run-canary", new string('2', 32),
            "2026-10-26T00:00:00.0000000Z", "2026-10-26T00:15:00.0000000Z");

        Assert.Equal(management, collector);
        // The Rust collector pins the same vector (tests/management_commands.rs).
        Assert.Equal(
            "{\"collectorId\":\"edge-01\",\"command\":\"run-canary\",\"commandId\":\"11111111111111111111111111111111\"," +
            "\"expiresAt\":\"2026-10-26T00:15:00.0000000Z\",\"issuedAt\":\"2026-10-26T00:00:00.0000000Z\"," +
            "\"kind\":\"bower.collector-command/v1\",\"nonce\":\"22222222222222222222222222222222\"}",
            System.Text.Encoding.UTF8.GetString(ManagementCommandSigner.SignedBytes(
                new string('1', 32), "edge-01", "run-canary", new string('2', 32),
                "2026-10-26T00:00:00.0000000Z", "2026-10-26T00:15:00.0000000Z")));
    }

    [Fact]
    public async Task Connectivity_StaleWithinTwoIntervalsThenOfflineAndUnhealthyAfterFifteenMinutesFailing()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);
        HttpClient viewer = Client(app, BowerRoles.Viewer);

        async Task<string?> ConnectivityAsync() =>
            (await viewer.GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct))!.Connectivity;

        await HeartbeatV2Async(collector, ct);
        string? fresh = await ConnectivityAsync();
        clock.Advance(TimeSpan.FromSeconds(120));
        string? atTwoIntervals = await ConnectivityAsync();
        clock.Advance(TimeSpan.FromSeconds(1));
        string? stale = await ConnectivityAsync();
        clock.Advance(TimeSpan.FromMinutes(14));
        string? offline = await ConnectivityAsync();

        // Delivery failing: unhealthy only after 15 minutes of consecutive failing heartbeats.
        await HeartbeatV2Async(collector, ct, delivery: "stalled");
        clock.Advance(TimeSpan.FromMinutes(14));
        await HeartbeatV2Async(collector, ct, delivery: "retrying");
        string? stillOnline = await ConnectivityAsync();
        clock.Advance(TimeSpan.FromMinutes(1));
        await HeartbeatV2Async(collector, ct, delivery: "stalled");
        string? unhealthy = await ConnectivityAsync();
        await HeartbeatV2Async(collector, ct, delivery: "healthy");
        string? recovered = await ConnectivityAsync();
        List<CollectorRecord>? listed = await viewer.GetFromJsonAsync<List<CollectorRecord>>("/api/collectors", Json, ct);

        Assert.Equal(CollectorConnectivity.Online, fresh);
        Assert.Equal(CollectorConnectivity.Online, atTwoIntervals);
        Assert.Equal(CollectorConnectivity.Stale, stale);
        Assert.Equal(CollectorConnectivity.Offline, offline);
        Assert.Equal(CollectorConnectivity.Online, stillOnline);
        Assert.Equal(CollectorConnectivity.Unhealthy, unhealthy);
        Assert.Equal(CollectorConnectivity.Online, recovered);
        Assert.Equal(CollectorConnectivity.Online, Assert.Single(listed!).Connectivity);
    }

    [Fact]
    public async Task Heartbeat_RejectsOutOfBoundsV2Fields()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, new FakeClock(Start), ct, out _);
        HttpClient collector = await EnrolAsync(app, ct);

        CollectorHeartbeat valid = V2Body([], [], "healthy", null, []);
        CollectorHeartbeat[] invalid =
        [
            valid with { HeartbeatIntervalSeconds = 1 },
            // Beyond 300 s two missed intervals would outlast the 15-minute offline threshold.
            valid with { HeartbeatIntervalSeconds = 301 },
            valid with { OldestUndeliveredAgeSeconds = -1 },
            valid with { CommandResults = [new CommandResultReport("not-hex", "succeeded", "x", Start)] },
            valid with { CommandResults = [new CommandResultReport(null, "executed", "x", Start)] },
            valid with
            {
                CommandResults = [.. Enumerable.Range(0, 33).Select(_ => new CommandResultReport(null, "failed", "x", Start))]
            }
        ];
        foreach (CollectorHeartbeat body in invalid)
        {
            using HttpResponseMessage response = await collector.PostAsJsonAsync(
                $"/api/collectors/{CollectorId}/heartbeat", body, ct);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    private static Task<WebApplication> StartAsync(
        TemporaryDirectory directory,
        TimeProvider clock,
        CancellationToken ct,
        out string publicPem)
    {
        (string privatePem, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "command-signing.pem");
        File.WriteAllText(keyFile, privatePem);
        publicPem = publicKey;
        return ManagementApiTests.StartAsync(directory, clock, ct, $"--{ManagementCommandSigner.KeyFileSetting}={keyFile}");
    }

    private static HttpClient Client(WebApplication app, string roles) => ManagementApiTests.Client(app, roles);

    private static async Task<AuditRecord[]> AuditAsync(WebApplication app, CancellationToken ct) =>
        (await Client(app, BowerRoles.Viewer).GetFromJsonAsync<AuditRecord[]>("/api/audit", ct))!;

    private static async Task<HttpClient> EnrolAsync(
        WebApplication app,
        CancellationToken ct,
        string collectorId = CollectorId)
    {
        HttpClient collector = Client(app, BowerRoles.Collector);
        using HttpResponseMessage registered = await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration(collectorId, collectorId, "test", "0.1.0", "c", "p", [], []),
            ct);
        using HttpResponseMessage approved = await Client(app, BowerRoles.Approver).PostAsJsonAsync(
            $"/api/approvals/{collectorId}/approve", new ApprovalRequest("Expected collector"), ct);
        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        return collector;
    }

    private static CollectorHeartbeat V2Body(
        IReadOnlyList<string> capabilities,
        IReadOnlyList<CommandResultReport> results,
        string delivery,
        CanaryReport? canary,
        IReadOnlyList<SourceReport> sources) =>
        new(
            "0.2.0", "c", "p", 3, delivery, sources, [], null, null, 0, null,
            SchemaVersion: 2,
            HeartbeatIntervalSeconds: 60,
            OldestUndeliveredAgeSeconds: 42,
            LastSuccessfulDeliveryAt: Start.AddSeconds(-30),
            LastCanary: canary,
            CommandCapabilities: capabilities,
            CommandResults: results);

    private static async Task<HeartbeatResponse> HeartbeatV2Async(
        HttpClient collector,
        CancellationToken ct,
        IReadOnlyList<string>? capabilities = null,
        IReadOnlyList<CommandResultReport>? results = null,
        string delivery = "healthy",
        CanaryReport? canary = null,
        IReadOnlyList<SourceReport>? sources = null,
        string collectorId = CollectorId)
    {
        using HttpResponseMessage response = await collector.PostAsJsonAsync(
            $"/api/collectors/{collectorId}/heartbeat",
            V2Body(capabilities ?? [], results ?? [], delivery, canary, sources ?? []),
            ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<HeartbeatResponse>(Json, ct))!;
    }
}
