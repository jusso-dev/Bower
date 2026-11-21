using System.Net;
using System.Net.Http.Json;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// Live visual pipeline telemetry (#101) and SQL Server guided source setup (#99):
/// heartbeat pipeline/activity counters, /api/pipelines/live, Operator-only audited tap,
/// and SQL Server plan validation + redacted preview.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class PipelineLiveAndSqlSetupTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task LivePipelines_SurfacesFiveStagesTopSourcesAndRedactions_AndTapEnforcesOperatorRbac()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory,
            services => services.AddSingleton<ICollectorTapClient>(new StubTapClient()),
            null,
            cancellation);

        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector, "sp-edge-01");
        HttpClient approver = ManagementApiTests.Client(app, BowerRoles.Approver, "approver-oid");
        HttpClient viewer = ManagementApiTests.Client(app, BowerRoles.Viewer, "viewer-oid");
        HttpClient oper = ManagementApiTests.Client(app, BowerRoles.Operator, "operator-oid");

        // Register & approve collector.
        using HttpResponseMessage reg = await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration(
                "edge-01",
                "edge-01.corp.example",
                "production",
                "1.0.1",
                "sha256:cfg",
                "sha256:pol",
                [new SourceReport("local-http", "local-http", "healthy", null, null)],
                [new OutputReport("azure-logs-ingestion", "azure-logs-ingestion", "healthy", null, null)]),
            cancellation);
        Assert.Equal(HttpStatusCode.Accepted, reg.StatusCode);

        using HttpResponseMessage approved = await approver.PostAsJsonAsync(
            "/api/approvals/edge-01/approve",
            new ApprovalRequest("Production edge collector"),
            cancellation);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);

        // Send heartbeat v2 with Pipeline, Activity and Redactions metadata.
        CollectorHeartbeat heartbeat = new(
            "1.0.1",
            "sha256:cfg",
            "sha256:pol",
            QueueDepth: 6,
            DeliveryStatus: "healthy",
            Sources: [new SourceReport("local-http", "local-http", "healthy", 0, Now)],
            Outputs: [new OutputReport("azure-logs-ingestion", "azure-logs-ingestion", "healthy", Now, null)],
            DeadLettered: 0,
            PrivacyProfileHash: "default",
            SchemaVersion: 2,
            HeartbeatIntervalSeconds: 60,
            OldestUndeliveredAgeSeconds: 15,
            LastSuccessfulDeliveryAt: Now,
            Redactions: new RedactionReport(Now.AddHours(-1), [new RedactionReportCount("au.tfn", 4)]),
            Pipeline: new PipelineReport(
                Now.AddHours(-1),
                EventsIn: 500,
                EventsQueued: 100,
                Duplicates: 5,
                Suppressed: 45,
                BytesIn: 250_000,
                BytesQueued: 50_000,
                Rows: [new PipelineRowReport("policy", "BWR-POL-AUTH-FAILURE", "accept", 100, 100, 0, 0, 50_000, 50_000)]),
            Activity: [new SourceActivityReport("portal", "production", Now, 100)]);

        using HttpResponseMessage hb = await collector.PostAsJsonAsync("/api/collectors/edge-01/heartbeat", heartbeat, cancellation);
        Assert.Equal(HttpStatusCode.OK, hb.StatusCode);

        // Viewer can inspect GET /api/pipelines/live.
        List<CollectorPipelineFlow> flows = (await viewer.GetFromJsonAsync<List<CollectorPipelineFlow>>(
            "/api/pipelines/live", ManagementApiTests.ApiJson, cancellation))!;
        CollectorPipelineFlow flow = Assert.Single(flows);
        Assert.Equal("edge-01", flow.CollectorId);
        Assert.Equal(5, flow.Stages.Count);
        Assert.Equal(["collect", "redact", "select", "queue", "deliver"], flow.Stages.Select(s => s.Id));
        Assert.Equal(80, flow.ReductionPercent);
        Assert.Equal("portal", Assert.Single(flow.TopSources).Application);
        Assert.Equal(4, Assert.Single(flow.Redactions).Events);

        // Viewer is forbidden from POST /api/pipelines/collectors/edge-01/tap.
        using HttpResponseMessage viewerTap = await viewer.PostAsJsonAsync(
            "/api/pipelines/collectors/edge-01/tap", new PipelineTapRequest(Limit: 5), cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, viewerTap.StatusCode);

        // Operator succeeds, receives redacted frames, and writes an audit row.
        using HttpResponseMessage opTap = await oper.PostAsJsonAsync(
            "/api/pipelines/collectors/edge-01/tap", new PipelineTapRequest(Source: "portal", Limit: 5), cancellation);
        Assert.Equal(HttpStatusCode.OK, opTap.StatusCode);
        PipelineTapResponse tapBody = (await opTap.Content.ReadFromJsonAsync<PipelineTapResponse>(ManagementApiTests.ApiJson, cancellation))!;
        Assert.Equal("live", tapBody.Mode);
        Assert.Single(tapBody.Frames);
        Assert.Contains("--source portal", tapBody.Command, StringComparison.Ordinal);

        List<AuditRecord> audits = (await viewer.GetFromJsonAsync<List<AuditRecord>>(
            "/api/audit", ManagementApiTests.ApiJson, cancellation))!;
        Assert.Contains(audits, row => row.Action == "pipeline.tap-sampled" && row.TargetId == "edge-01");
    }

    [Fact]
    public async Task SqlServerGuidedSource_ValidatesSecretRefAndBuildsReadOnlyPlanAndRedactedPreview()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellation);
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector, "sp-sql-01");
        HttpClient approver = ManagementApiTests.Client(app, BowerRoles.Approver, "approver-oid");
        HttpClient oper = ManagementApiTests.Client(app, BowerRoles.Operator, "operator-oid");

        await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration("sql-01", "sql-01.corp.example", "production", "1.0.1", "sha256:c", "sha256:p", [], []),
            cancellation);
        await approver.PostAsJsonAsync("/api/approvals/sql-01/approve", new ApprovalRequest("SQL collector"), cancellation);

        Dictionary<string, string> validValues = new()
        {
            ["sourceId"] = "sql-audit-primary",
            ["schema"] = "dbo",
            ["table"] = "SecurityAuditLog",
            ["cursorKind"] = "Timestamp",
            ["timestampOverlapSeconds"] = "300",
            ["pollIntervalSeconds"] = "30",
            ["batchSize"] = "500",
            ["connectionStringRef"] = "/run/secrets/bower-sql-readonly",
            ["application"] = "core-db",
            ["environment"] = "production",
            ["maximumSilenceMinutes"] = "60"
        };

        using HttpResponseMessage ok = await oper.PostAsJsonAsync(
            "/api/sources/plan", new SourceSetupDraft("sql-server", "sql-01", validValues), cancellation);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        SourceSetupPlanResult planResult = (await ok.Content.ReadFromJsonAsync<SourceSetupPlanResult>(ManagementApiTests.ApiJson, cancellation))!;
        Assert.True(planResult.Valid);
        Assert.NotNull(planResult.Plan);
        Assert.Contains(planResult.Plan!.Files, f => f.Name == "sql-server.json" && f.Content.Contains("SecurityAuditLog", StringComparison.Ordinal));
        Assert.Contains(planResult.Plan.Snippets, s => s.Content.Contains("GRANT SELECT ON [dbo].[SecurityAuditLog]", StringComparison.Ordinal));
        Assert.NotNull(planResult.Preview);
        Assert.True(planResult.Preview!.Valid);
        // Synthetic sample contains a TFN which must be redacted before returning to the browser.
        Assert.DoesNotContain("123 456 782", planResult.Preview.Redacted!, StringComparison.Ordinal);

        // Reject inline password / raw connection string instead of secret reference.
        Dictionary<string, string> badValues = new(validValues)
        {
            ["connectionStringRef"] = "Server=sql01;Database=Audit;User Id=sa;Password=SuperSecret123!;"
        };
        using HttpResponseMessage bad = await oper.PostAsJsonAsync(
            "/api/sources/plan", new SourceSetupDraft("sql-server", "sql-01", badValues), cancellation);
        SourceSetupPlanResult badResult = (await bad.Content.ReadFromJsonAsync<SourceSetupPlanResult>(ManagementApiTests.ApiJson, cancellation))!;
        Assert.False(badResult.Valid);
    }

    private sealed class StubTapClient : ICollectorTapClient
    {
        public Task<IReadOnlyList<PipelineTapFrame>?> TrySampleAsync(
            string collectorId,
            PipelineTapRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<PipelineTapFrame>?>([
                new PipelineTapFrame(
                    Now,
                    "policy",
                    "redact-and-accept",
                    "authentication_failure",
                    "portal/production",
                    "BWR-POL-AUTH-FAILURE",
                    "{\"eventType\":\"authentication_failure\",\"actor\":{\"username\":\"[MASKED]\"}}")
            ]);
    }
}
