using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Source.Aws;

namespace Bower.UnitTests;

/// <summary>
/// The cloud-agent quick starts (docs/getting-started/aws-cloudwatch-agent.md and
/// azure-monitor-agent.md): the sample event is a valid envelope that the AWS forwarder would
/// pick out of CloudWatch Logs, the CloudWatch agent filter keeps it, and the AMA spool rule
/// lands rows in BowerSecurity_CL exactly as the Logs Ingestion API rule does.
/// </summary>
public sealed partial class CloudAgentQuickStartTests
{
    private static string Examples => Path.Combine(AppContext.BaseDirectory, "examples", "cloud-agents");

    private static string SampleEvent => File.ReadAllLines(Path.Combine(Examples, "sample-event.jsonl")).Single(line => line.Length > 0);

    [Fact]
    public void SampleEvent_MatchesTheEnvelopeSchema()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "schemas", "envelope", "security-event.schema.json")));
        using JsonDocument sample = JsonDocument.Parse(SampleEvent);
        List<string> errors = [];

        AsvsExampleContractTests.Validate(sample.RootElement, schema.RootElement, schema.RootElement, "$", errors);

        Assert.True(errors.Count == 0, string.Join("; ", errors));
    }

    [Theory]
    [InlineData("amazon-cloudwatch-agent.json")]
    [InlineData("amazon-cloudwatch-agent.windows.json")]
    public void CloudWatchAgentFilter_KeepsBowerEventsAndTheForwarderFindsThem(string file)
    {
        using JsonDocument config = JsonDocument.Parse(File.ReadAllText(Path.Combine(Examples, "aws", file)));
        JsonElement entry = config.RootElement.GetProperty("logs").GetProperty("logs_collected").GetProperty("files")
            .GetProperty("collect_list").EnumerateArray().Single();
        JsonElement filter = entry.GetProperty("filters").EnumerateArray().Single();

        Assert.Equal("/bower/app-events", entry.GetProperty("log_group_name").GetString());
        Assert.Equal("include", filter.GetProperty("type").GetString());
        Regex include = new(filter.GetProperty("expression").GetString()!, RegexOptions.None, TimeSpan.FromSeconds(1));
        Assert.Matches(include, SampleEvent);
        Assert.DoesNotMatch(include, "2026-11-10 INFO GET /health 200");

        // What the bower-cloud agent extracts from a CloudWatch Logs message is the line itself.
        Assert.Equal(SampleEvent, FirehoseLogObjectReader.TryExtractEnvelope(SampleEvent));
    }

    [Fact]
    public void AmaSpoolRule_UsesTheSameStreamColumnsAndTransformAsTheIngestionRule()
    {
        string main = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"));
        string spool = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "ama-spool-dcr.bicep"));

        Assert.Equal(StreamColumns(main, "'Custom-BowerSecurity': {"), StreamColumns(spool, "'Custom-BowerSpool': {"));
        Assert.Equal(Normalise(Transform(main)), Normalise(Transform(spool)));
        Assert.Contains("outputStream: 'Custom-BowerSecurity_CL'", spool, StringComparison.Ordinal);
        Assert.Contains("format: 'json'", spool, StringComparison.Ordinal);
        Assert.Contains("dataCollectionEndpointId: dataCollectionEndpointId", spool, StringComparison.Ordinal);
        Assert.Contains("'/var/spool/bower/ready/*.jsonl'", spool, StringComparison.Ordinal);
    }

    private static string[] StreamColumns(string bicep, string marker)
    {
        int start = bicep.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{marker} not found");
        int end = bicep.IndexOf(']', start);
        return [.. ColumnPattern().Matches(bicep[start..end]).Select(match => $"{match.Groups["name"].Value}:{match.Groups["type"].Value}")];
    }

    private static string Transform(string bicep) =>
        Regex.Match(bicep, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Groups["kql"].Value;

    private static string Normalise(string kql) => Regex.Replace(kql, @"\s+", " ").Trim();

    [GeneratedRegex(@"\{ name: '(?<name>[^']+)', type: '(?<type>[^']+)' \}")]
    private static partial Regex ColumnPattern();
}
