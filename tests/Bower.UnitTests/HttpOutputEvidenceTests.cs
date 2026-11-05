using System.Text.Json.Nodes;
using Bower.Evidence;

namespace Bower.UnitTests;

/// <summary>
/// Evidence for a collector whose output is <c>http</c> never claims Sentinel delivery.
/// Mirrored in rust/crates/bower-evidence/tests/http_output_evidence.rs.
/// </summary>
public sealed class HttpOutputEvidenceTests
{
    private const string Workspace = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task Canary_ForAnHttpOutputFailsWithoutQueryingSentinel()
    {
        StatusCollector collector = new("http");
        RowQuery query = new();

        EvidenceBundle bundle = await new EvidenceRunner(collector, query, null)
            .RunAsync(Options(Workspace), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.False(bundle.Arrival.Found);
        Assert.Equal(ProbeOutcomes.OutputNotSentinel, bundle.Arrival.QueryError);
        Assert.Contains(bundle.Limitations, item => item.StartsWith("NOT SENTINEL:", StringComparison.Ordinal));
        // The canary was still sent through the real pipeline, but Sentinel was never asked for it.
        Assert.Equal(1, collector.Canaries);
        Assert.DoesNotContain(query.Queries, kql => kql.Contains(bundle.Canary.EventId, StringComparison.Ordinal));
        Assert.All(bundle.Controls, control => Assert.NotEqual("verified", control.Status));
    }

    [Fact]
    public async Task SimulatedCanaryForAnHttpOutputSaysItIsNotSentinel()
    {
        EvidenceBundle bundle = await new EvidenceRunner(new StatusCollector("http"), null, null)
            .RunAsync(Options(null), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Simulated, bundle.Mode);
        Assert.Contains(bundle.Limitations, item => item.StartsWith("NOT SENTINEL:", StringComparison.Ordinal));
        Assert.Contains(bundle.Limitations, item => item.StartsWith("SIMULATED:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SentinelOutputsStillVerifyByQuery()
    {
        StatusCollector collector = new("azure-logs-ingestion");

        EvidenceBundle bundle = await new EvidenceRunner(collector, new RowQuery(), null)
            .RunAsync(Options(Workspace), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        Assert.DoesNotContain(bundle.Limitations, item => item.StartsWith("NOT SENTINEL:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ParserProbe_ForAnHttpOutputIsNotSentOrQueried()
    {
        StatusCollector collector = new("http");
        RowQuery query = new();

        EvidenceBundle bundle = await new EvidenceRunner(collector, query, null)
            .RunAsync(Options(Workspace) with { ProbeProfile = "parser:linux-ssh-gateway:0" }, TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(ProbeOutcomes.OutputNotSentinel, bundle.Probe!.Outcome);
        Assert.Equal(ProbeOutcomes.OutputNotSentinel, bundle.Arrival.QueryError);
        Assert.Equal(0, collector.Records);
        Assert.Contains(bundle.Limitations, item => item.StartsWith("NOT SENTINEL:", StringComparison.Ordinal));
        Assert.DoesNotContain(query.Queries, kql => kql.Contains(bundle.Probe.EventId, StringComparison.Ordinal));
    }

    private static EvidenceOptions Options(string? workspace) => new()
    {
        CollectorUrl = new Uri("http://collector.test:4319/"),
        WorkspaceId = workspace,
        PollInterval = TimeSpan.Zero,
        Timeout = TimeSpan.FromSeconds(5)
    };

    /// <summary>A collector reporting <paramref name="output"/> in <c>/v1/status</c>, with an active SSH parser.</summary>
    private sealed class StatusCollector(string output) : ICanarySender, IParserProbeSender
    {
        public int Canaries { get; private set; }

        public int Records { get; private set; }

        public Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
        {
            Canaries++;
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject { ["decision"] = "accept" }));
        }

        public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken) =>
            Task.FromResult<(int, JsonObject?)>((200, new JsonObject
            {
                ["output"] = output,
                ["policy"] = new JsonObject
                {
                    ["hash"] = "sha256:bundle",
                    ["packs"] = new JsonArray(new JsonObject
                    {
                        ["id"] = "linux-ssh-gateway",
                        ["version"] = "1.1.0",
                        ["packHash"] = "sha256:pack",
                        ["parserStatuses"] = new JsonArray("active-local-json")
                    })
                }
            }));

        public Task<(int Status, JsonObject? Body)> SendRecordAsync(
            Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken)
        {
            Records++;
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject()));
        }
    }

    /// <summary>A destination that returns a row for any canary query.</summary>
    private sealed class RowQuery : ILogAnalyticsQuery
    {
        public List<string> Queries { get; } = [];

        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            Queries.Add(kql);
            return Task.FromResult(kql.StartsWith("DCRLogErrors", StringComparison.Ordinal)
                ? new QueryRows([new Dictionary<string, JsonNode?> { ["Errors"] = 0 }], null)
                : new QueryRows(
                    [new Dictionary<string, JsonNode?>
                    {
                        ["TimeGenerated"] = "2026-11-05T01:02:03Z",
                        ["IngestionTime"] = "2026-11-05T01:03:03Z",
                        ["PolicyHash"] = "sha256:policy"
                    }],
                    null));
        }
    }
}
