using System.Text.RegularExpressions;
using Bower.Dcr;

namespace Bower.UnitTests;

/// <summary>
/// Static checks for the replay-safe Sentinel content in deploy/sentinel/analytics.
/// These checks do not execute Kusto or prove alert behaviour; the live Sentinel campaign
/// in docs/evidence/ws2b-* does (see docs/production-readiness/02-replay-safe-detections.md).
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
        Assert.Matches(@"\ABowerSecurity_CL\s*\|\s*where EventType !in \(""collector_health"", ""collector_canary""\)\s*\|\s*extend BowerIngested = ingestion_time\(\)\s*\|\s*summarize arg_min\(BowerIngested, \*\), BowerLastIngested = max\(BowerIngested\), BowerCopies = count\(\)\s+by CollectorId, EventId\b", Code(parser));
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
        // Catch-up retries only every second run: a run cannot see the previous run's alerts
        // (their TimeGenerated is after its window end); live run ws2 found duplicates otherwise.
        Assert.Contains("| where Slot == 0 or (Slot >= retrySpacing and Slot % retrySpacing == 0)", query, StringComparison.Ordinal);
        Assert.Matches(@"BowerSecurityEventsOfType\(dynamic\(\[""[a-z_]+""\]\)\)", query);
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
            Assert.Contains($"let retrySpacing = {Default("alertVisibilityRuns")};", query, StringComparison.Ordinal);
        }

        Assert.Contains($"let threshold = {Default("bruteForceThreshold")};", Read("rules", "wec-brute-force.kql"), StringComparison.Ordinal);
        Assert.Contains($"let threshold = {Default("firewallDenyThreshold")};", Read("rules", "firewall-deny.kql"), StringComparison.Ordinal);
        Assert.Contains($"tune(loadTextContent('rules/wec-brute-force.kql'), {Default("bruteForceThreshold")},", bicep, StringComparison.Ordinal);
        Assert.Contains($"tune(loadTextContent('rules/firewall-deny.kql'), {Default("firewallDenyThreshold")},", bicep, StringComparison.Ordinal);
        string tolerance = Read("rules", "beyond-tolerance.kql");
        Assert.Contains($"let maxDelay = {Default("maxIngestionDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains($"let settleDelay = {Default("settleDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains($"let frequency = {Default("toleranceFrequencyMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains("'let frequency = 60m;', 'let frequency = ${toleranceFrequencyMinutes}m;'", bicep, StringComparison.Ordinal);
        Assert.Contains("queryFrequency: 'PT${toleranceFrequencyMinutes}M'", bicep, StringComparison.Ordinal);
        Assert.Contains("'let retrySpacing = 2;', 'let retrySpacing = ${spacing};'", bicep, StringComparison.Ordinal);
    }

    [Fact]
    public void TypedParser_FiltersBeforeCollapsingWithTheSameIdentityAndCopies()
    {
        string full = Code(Read("bower-security-events.kql"));
        string typed = Code(Read("bower-security-events-of-type.kql"));
        string Collapse(string query) => Regex.Match(query, @"\| summarize arg_min.*?by CollectorId, EventId", RegexOptions.Singleline).Value;

        // Same first copy, last ingestion and copy count per (CollectorId, EventId).
        Assert.NotEmpty(Collapse(full));
        Assert.Equal(Collapse(full), Collapse(typed));
        int filter = typed.IndexOf("where EventType in (eventTypes)", StringComparison.Ordinal);
        int dropped = typed.IndexOf("project-away RawEnvelope", StringComparison.Ordinal);
        int collapse = typed.IndexOf("summarize arg_min", StringComparison.Ordinal);
        Assert.True(filter >= 0 && filter < dropped && dropped < collapse);
        // The event time is read from RawEnvelope before it is dropped.
        Assert.True(typed.IndexOf("BowerEventTime = coalesce(todatetime(RawEnvelope.timeGenerated)", StringComparison.Ordinal) < dropped);
        Assert.Contains("functionParameters: 'eventTypes:dynamic'", Read("main.bicep"), StringComparison.Ordinal);
        // Columns the detection rules read are kept.
        string projectAway = typed[dropped..typed.IndexOf('\n', dropped)];
        foreach (string column in new[] { "EventType", "EventResult", "ApplicationName", "SourceIpAddress", "ActorUsername", "TimeGenerated" })
        {
            Assert.DoesNotContain(column, projectAway, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Bicep_FailsWhenCatchUpLeavesNoRetrySlot()
    {
        string bicep = Read("main.bicep").ReplaceLineEndings("\n");

        // Retries run in slots alertVisibilityRuns, 2 x alertVisibilityRuns, ...
        Assert.Contains("catchUpMinutes >= (alertVisibilityRuns + 1) * frequencyMinutes", bicep, StringComparison.Ordinal);
        Assert.Contains(": fail('catchUpMinutes must be at least (alertVisibilityRuns + 1) x frequencyMinutes", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("catchUpMinutes, maxIngestionDelayMinutes", bicep, StringComparison.Ordinal);
        Assert.Equal(2, Regex.Count(bicep, "catchUpMinutesChecked, maxIngestionDelayMinutes, bucketMinutes, alertVisibilityRuns"));
    }

    [Fact]
    public void ToleranceMonitor_AlertsOnceAndIgnoresReplaysOfOldEvents()
    {
        string query = Code(Read("rules", "beyond-tolerance.kql"));

        // One non-overlapping first-ingestion slot per run.
        Assert.Contains("let windowStart = windowEnd - frequency;", query, StringComparison.Ordinal);
        Assert.Contains("where BowerIngested >= windowStart and BowerIngested < windowEnd", query, StringComparison.Ordinal);
        // A row with an earlier copy is a replay, even when its TimeGenerated was rewritten.
        Assert.Contains("| where ingestion_time() < windowStart", query, StringComparison.Ordinal);
        Assert.Contains("| join kind=leftanti earlier on CollectorId, EventId", query, StringComparison.Ordinal);
        Assert.Contains("queryPeriod: 'P14D'", Read("main.bicep"), StringComparison.Ordinal);
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
            "var queryPeriodMinutes = maxIngestionDelayMinutes + bucketMinutes + catchUpMinutesChecked + settleDelayMinutes + 10",
            bicep,
            StringComparison.Ordinal);
        // Azure Monitor rewrites event times older than two days; the tolerance stays below it.
        Assert.Contains("@maxValue(2820)\nparam maxIngestionDelayMinutes", bicep.ReplaceLineEndings("\n"), StringComparison.Ordinal);
    }

    /// <summary>The query without whole-line // comments.</summary>
    private static string Code(string kql) => string.Join('\n', kql.ReplaceLineEndings("\n").Split('\n')
        .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal))).Trim();
}
