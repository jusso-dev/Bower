using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Output.Syslog;
using Bower.Source.Aws;

namespace Bower.UnitTests;

/// <summary>
/// The cloud-agent quick starts (docs/getting-started/aws-cloudwatch-agent.md and
/// azure-monitor-agent.md): the sample event is a valid envelope that the AWS forwarder would
/// pick out of CloudWatch Logs, the CloudWatch agent filter keeps it, and the AMA syslog rule
/// decodes Bower's syslog messages into the same BowerSecurity_CL columns as the Logs Ingestion API rule.
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
    public void AmaSyslogRule_ProjectsTheSameColumnsAsTheIngestionRuleFromTheDecodedEnvelope()
    {
        string main = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"));
        string syslog = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "ama-syslog-dcr.bicep"));
        string transform = Normalise(Transform(syslog));

        // Every main.bicep projection, read from the decoded envelope e instead of the stream.
        string[] columns = StreamColumnNames(main);
        string expected = Regex.Replace(Normalise(Transform(main)).Split("| project ", 2)[1], $@"(?<![.\w])({string.Join('|', columns.OrderByDescending(name => name.Length))})(?!\w)", "e.$1")
            .Replace("pack_all()", "e", StringComparison.Ordinal)
            .Replace("TimeGenerated = e.timeGenerated", "TimeGenerated = todatetime(e.timeGenerated)", StringComparison.Ordinal)
            .Replace("TimeObserved = e.timeObserved", "TimeObserved = todatetime(e.timeObserved)", StringComparison.Ordinal);
        Assert.Equal(expected, transform.Split("| project ", 2)[1]);

        Assert.StartsWith(
            "source | where SyslogMessage contains_cs \"bower-b64:\" | extend e = parse_json(base64_decodestring(substring(SyslogMessage, indexof(SyslogMessage, \"bower-b64:\") + 10))) | where tostring(e.schemaVersion) == \"1.0.0\"",
            transform,
            StringComparison.Ordinal);
        Assert.Contains($"\"{SyslogOutput.MessagePrefix}\") + {SyslogOutput.MessagePrefix.Length})", transform, StringComparison.Ordinal);
        Assert.Contains("outputStream: 'Custom-BowerSecurity_CL'", syslog, StringComparison.Ordinal);
        Assert.Contains("streams: ['Microsoft-Syslog']", syslog, StringComparison.Ordinal);
        Assert.Contains("param facility string = 'local4'", syslog, StringComparison.Ordinal);
        // Notice and above: Bower writes at notice, so a lower minimum would only add noise.
        Assert.Contains("logLevels: ['Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']", syslog, StringComparison.Ordinal);
    }

    [Fact]
    public void SyslogOutputDefaults_MatchTheRule()
    {
        SyslogOutputOptions options = new() { Id = "syslog" };

        Assert.Equal((20, 5, "/dev/log"), (options.Facility, options.Severity, options.SocketPath));
    }

    private static string[] StreamColumnNames(string bicep)
    {
        int start = bicep.IndexOf("'Custom-BowerSecurity': {", StringComparison.Ordinal);
        Assert.True(start >= 0);
        int end = bicep.IndexOf(']', start);
        return [.. ColumnPattern().Matches(bicep[start..end]).Select(match => match.Groups["name"].Value)];
    }

    private static string Transform(string bicep) =>
        Regex.Match(bicep, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Groups["kql"].Value;

    private static string Normalise(string kql) => Regex.Replace(kql, @"\s+", " ").Trim();

    [GeneratedRegex(@"\{ name: '(?<name>[^']+)', type: '(?<type>[^']+)' \}")]
    private static partial Regex ColumnPattern();
}
