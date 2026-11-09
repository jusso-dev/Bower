using System.Text.Json.Nodes;
using Bower.Evidence;

namespace Bower.UnitTests;

/// <summary>
/// Evidence never claims Sentinel delivery for an output outside the Sentinel allowlist.
/// </summary>
public sealed class HttpOutputEvidenceTests
{
    private const string Workspace = "00000000-0000-0000-0000-000000000001";

    [Theory]
    [InlineData("http", null, "http")]
    [InlineData("http", "parser:linux-ssh-gateway:0", "http")]
    [InlineData("s3", null, "s3")]
    [InlineData("future-output", "parser:linux-ssh-gateway:0", "future-output")]
    [InlineData("Not An Id!", null, "unknown")]
    public async Task NonSentinelOutput_IsRefusedWithoutSendingACanaryOrQuerying(string output, string? profile, string label)
    {
        StatusCollector collector = new(output);
        RowQuery query = new();
        EvidenceOptions options = Options(Workspace) with { ProbeProfile = profile ?? ProbeProfiles.Generic };

        EvidenceBundle bundle = await new EvidenceRunner(collector, query, null)
            .RunAsync(options, TestContext.Current.CancellationToken);
        EvidenceBundle simulated = await new EvidenceRunner(collector, null, null)
            .RunAsync(options with { WorkspaceId = null }, TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(EvidenceModes.Simulated, simulated.Mode);
        Assert.False(bundle.Arrival.Found);
        Assert.Equal(ProbeOutcomes.CollectorOutputNotSentinel, bundle.Arrival.QueryError);
        Assert.Contains(ProbeOutcomes.NonSentinelLimitation(label), bundle.Limitations);
        Assert.Contains(ProbeOutcomes.NonSentinelLimitation(label), simulated.Limitations);
        Assert.Equal(0, collector.Canaries + collector.Records);
        Assert.DoesNotContain(query.Queries, kql => kql.Contains(bundle.Canary.EventId, StringComparison.Ordinal));
        if (profile is not null)
        {
            Assert.Equal(ProbeOutcomes.CollectorOutputNotSentinel, bundle.Probe!.Outcome);
        }
    }

    [Theory]
    [InlineData("azure-logs-ingestion", 200)]
    [InlineData("ama-spool", 200)]
    [InlineData("relay", 200)]
    [InlineData(null, 200)]
    [InlineData("http", 503)]
    public async Task SentinelRelayMissingOrUnreadableOutput_ProceedsAndOnlyTheQueryVerifies(string? output, int statusCode)
    {
        StatusCollector collector = new(output, statusCode);

        EvidenceBundle bundle = await new EvidenceRunner(collector, new RowQuery(), null)
            .RunAsync(Options(Workspace), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        Assert.Equal(1, collector.Canaries);
        Assert.DoesNotContain(bundle.Limitations, item => item.StartsWith("NOT SENTINEL:", StringComparison.Ordinal));
    }

    private static EvidenceOptions Options(string? workspace) => new()
    {
        CollectorUrl = new Uri("http://collector.test:4319/"),
        WorkspaceId = workspace,
        PollInterval = TimeSpan.Zero,
        Timeout = TimeSpan.FromSeconds(5)
    };

    /// <summary>A collector reporting <paramref name="output"/> in <c>/v1/status</c> (omitted when null), with an active SSH parser.</summary>
    private sealed class StatusCollector(string? output, int statusCode = 200) : ICanarySender, IParserProbeSender
    {
        public int Canaries { get; private set; }

        public int Records { get; private set; }

        public Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
        {
            Canaries++;
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject { ["decision"] = "accept" }));
        }

        public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken) =>
            Task.FromResult<(int, JsonObject?)>((statusCode, new JsonObject
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
