using System.Text.RegularExpressions;
using Bower.Dcr;

namespace Bower.UnitTests;

/// <summary>
/// Static checks for the replay-safe Sentinel content in deploy/sentinel/analytics.
/// These checks do not execute Kusto or prove alert behaviour. Live validation of the
/// current query and its replay, outage and incident behaviour remains open.
/// </summary>
public sealed class SentinelAnalyticsContentTests
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "deploy", "sentinel", "analytics");
    private static readonly string[] DetectionRules = ["wec-brute-force.kql", "firewall-deny.kql"];

    private static string Read(params string[] path) => File.ReadAllText(Path.Combine([Root, .. path]));

    private static HashSet<string> TableColumns() =>
        SentinelSchema.Default.TableColumns.Select(column => column.Name).ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void Parser_CollapsesReplaysByCollectorAndEventIdentity()
    {
        string parser = Read("bower-security-events.kql");

        Assert.StartsWith("BowerSecurity_CL", Code(parser), StringComparison.Ordinal);
        Assert.Contains("extend BowerIngested = ingestion_time()", parser, StringComparison.Ordinal);
        // Copies delivered by the same collector collapse to the earliest row.
        Assert.Matches(@"\ABowerSecurity_CL\s*\|\s*extend BowerIngested = ingestion_time\(\)\s*\|\s*summarize arg_min\(BowerIngested, \*\), BowerLastIngested = max\(BowerIngested\), BowerCopies = count\(\)\s+by CollectorId, EventId\b", Code(parser));
        Assert.Contains("todatetime(RawEnvelope.timeGenerated)", parser, StringComparison.Ordinal);
        HashSet<string> columns = TableColumns();
        foreach (string column in new[] { "CollectorId", "EventId", "TimeGenerated", "RawEnvelope", "Labels" })
        {
            Assert.Contains(column, columns);
        }
    }

    [Fact]
    public void Parser_ForgedReplayLabelsCannotSelectAnotherCollectorsIdentity()
    {
        string query = Code(Read("bower-security-events.kql"));

        // An ordinary authenticated producer can set either replay label. Neither can
        // participate in a grouping, filtering or identity expression in this query.
        Assert.DoesNotContain("Labels", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bowerReplay", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BowerOriginCollectorId", query, StringComparison.OrdinalIgnoreCase);
        Assert.Matches(@"\bby CollectorId, EventId\b", query);
    }

    [Theory]
    [InlineData("wec-brute-force.kql", new[] { "EventType", "ApplicationName", "SourceIpAddress", "ActorUsername", "CollectorId", "EventId" })]
    [InlineData("firewall-deny.kql", new[] { "EventType", "EventResult", "ApplicationName", "SourceIpAddress", "CollectorId", "EventId" })]
    public void DetectionRules_ReadTheParserAndCountExactly(string file, string[] usedColumns)
    {
        string query = Code(Read("rules", file));

        // Raw rows include replays; only the parser's collapsed rows are counted.
        Assert.DoesNotContain("BowerSecurity_CL", query, StringComparison.Ordinal);
        Assert.Contains("BowerSecurityEvents", query, StringComparison.Ordinal);
        Assert.DoesNotContain("dcount", query, StringComparison.Ordinal);
        Assert.DoesNotContain("ingestion_time()", query, StringComparison.Ordinal);
        // Late events are evaluated by first ingestion; replays never move a crossing.
        Assert.Contains("CrossedAt = minif(BowerFirstIngested, Rank == threshold)", query, StringComparison.Ordinal);
        Assert.Contains("BowerDetectionKey !in (alerted)", query, StringComparison.Ordinal);
        // The proposed mitigation retries only every second run; its live behaviour
        // remains unverified after a prior test found duplicate alerts.
        Assert.Contains("| where Slot == 0 or (Slot >= 2 and Slot % 2 == 0)", query, StringComparison.Ordinal);
        Assert.Contains("bin(BowerEventTime, bucketSize)", query, StringComparison.Ordinal);
        HashSet<string> columns = TableColumns();
        foreach (string column in usedColumns)
        {
            Assert.Contains(column, columns);
            Assert.Contains(column, query, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Bicep_DefaultsMatchTheRuleFilesAndEveryTuningAnchorExists()
    {
        string bicep = Read("main.bicep");
        int Default(string name) => int.Parse(
            Regex.Match(bicep, $@"param {name} int = (?<value>\d+)").Groups["value"].Value,
            System.Globalization.CultureInfo.InvariantCulture);

        // The files run unchanged in Logs with the deployed defaults, and a missing anchor
        // would make Bicep's replace() silently keep the default.
        foreach (string file in DetectionRules)
        {
            string query = Read("rules", file);
            Assert.Contains($"let settleDelay = {Default("settleDelayMinutes")}m;", query, StringComparison.Ordinal);
            Assert.Contains($"let frequency = {Default("frequencyMinutes")}m;", query, StringComparison.Ordinal);
            Assert.Contains($"let catchUp = {Default("catchUpMinutes")}m;", query, StringComparison.Ordinal);
            Assert.Contains($"let maxDelay = {Default("maxIngestionDelayMinutes")}m;", query, StringComparison.Ordinal);
            Assert.Contains($"let bucketSize = {Default("bucketMinutes")}m;", query, StringComparison.Ordinal);
        }

        Assert.Contains($"let threshold = {Default("bruteForceThreshold")};", Read("rules", "wec-brute-force.kql"), StringComparison.Ordinal);
        Assert.Contains($"let threshold = {Default("firewallDenyThreshold")};", Read("rules", "firewall-deny.kql"), StringComparison.Ordinal);
        Assert.Contains($"tune(loadTextContent('rules/wec-brute-force.kql'), {Default("bruteForceThreshold")},", bicep, StringComparison.Ordinal);
        Assert.Contains($"tune(loadTextContent('rules/firewall-deny.kql'), {Default("firewallDenyThreshold")},", bicep, StringComparison.Ordinal);
        string tolerance = Read("rules", "beyond-tolerance.kql");
        Assert.Contains($"let maxDelay = {Default("maxIngestionDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains($"let settleDelay = {Default("settleDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
    }

    [Fact]
    public void Bicep_RulesNeverSuppressAndAlertPerEntity()
    {
        string bicep = Read("main.bicep");

        // Suppression pauses evaluation for every entity, so late events would be missed.
        Assert.Equal(3, Regex.Count(bicep, "suppressionEnabled: false"));
        Assert.DoesNotContain("suppressionEnabled: true", bicep, StringComparison.Ordinal);
        Assert.Equal(3, Regex.Count(bicep, "aggregationKind: 'AlertPerResult'"));
        Assert.Contains("groupByEntities: ['IP']", bicep, StringComparison.Ordinal);
        Assert.Contains("param enableRules bool = false", bicep, StringComparison.Ordinal);
        // The TimeGenerated look-back covers the oldest evaluated bucket of a catch-up run.
        Assert.Contains(
            "var queryPeriodMinutes = maxIngestionDelayMinutes + bucketMinutes + catchUpMinutes + settleDelayMinutes + 10",
            bicep,
            StringComparison.Ordinal);
        // Azure Monitor rewrites event times older than two days; the tolerance stays below it.
        Assert.Contains("@maxValue(2820)\nparam maxIngestionDelayMinutes", bicep.ReplaceLineEndings("\n"), StringComparison.Ordinal);
    }

    /// <summary>The query without whole-line // comments.</summary>
    private static string Code(string kql) => string.Join('\n', kql.ReplaceLineEndings("\n").Split('\n')
        .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal))).Trim();
}
