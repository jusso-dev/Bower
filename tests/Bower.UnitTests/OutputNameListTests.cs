using System.Text.Json;
using Bower.Collector;
using Bower.Evidence;

namespace Bower.UnitTests;

/// <summary>
/// The output names live in separate lists (#251 items 5 and 6): what CollectorSettings accepts
/// for BOWER_OUTPUT, the settings schema, and ProbeOutcomes.SentinelOutputs. These tests read
/// CollectorSettings through its public API only, by trying each candidate value.
/// </summary>
public sealed class OutputNameListTests
{
    // Every output name used anywhere in Bower, plus names a reader might try. A new output
    // must be added here (and so to one of the classifications below) for these tests to see it.
    private static readonly string[] Candidates =
    [
        "none", "ama-spool", "azure-logs-ingestion", "relay", "s3", "http", "syslog",
        "kafka", "security-lake", "opensearch", "azure-monitor", "ama-syslog", "local-syslog", "splunk"
    ];

    // Accepted outputs that never deliver to Microsoft Sentinel: no evidence probe is sent.
    private static readonly string[] NotSentinel = ["none", "s3", "http"];

    private const string Unsupported = "Unsupported BOWER_OUTPUT value";

    private static bool Accepted(string output)
    {
        try
        {
            CollectorSettings.FromEnvironment(name => name switch
            {
                "BOWER_COLLECTOR_ID" => "output-name-list",
                "BOWER_OUTPUT" => output,
                _ => null
            });
            return true;
        }
        catch (InvalidOperationException error) when (!error.Message.StartsWith(Unsupported, StringComparison.Ordinal))
        {
            // Accepted as an output; refused only for its missing settings (endpoint, bucket, ...).
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static string[] AcceptedOutputs() => [.. Candidates.Where(Accepted).Order(StringComparer.Ordinal)];

    [Fact]
    public void Accepted_RefusesAnUnknownName()
    {
        Assert.False(Accepted("azure-monitor"));
        Assert.True(Accepted("none"));
    }

    [Fact]
    public void Schema_ListsEveryOutputCollectorSettingsAccepts()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "schemas", "configuration", "collector-configuration.schema.json")));
        string[] listed =
        [
            .. schema.RootElement.GetProperty("properties").GetProperty("outputs").GetProperty("items")
                .GetProperty("properties").GetProperty("type").GetProperty("enum").EnumerateArray()
                .Select(item => item.GetString()!)
                .Order(StringComparer.Ordinal)
        ];

        // "none" is the absence of an output, so it is not an output entry in the schema.
        Assert.Equal(AcceptedOutputs().Where(output => output != "none"), listed);
    }

    [Fact]
    public void SentinelOutputs_ListsEveryAcceptedOutputThatDeliversToSentinel()
    {
        string[] sentinel = [.. AcceptedOutputs().Except(NotSentinel, StringComparer.Ordinal)];

        // Fails when an output is accepted but neither listed for evidence nor declared not-Sentinel.
        Assert.Equal(sentinel, ProbeOutcomes.SentinelOutputs.Order(StringComparer.Ordinal));
        Assert.All(NotSentinel, output => Assert.True(Accepted(output), $"{output} is no longer accepted; update NotSentinel."));
    }
}
