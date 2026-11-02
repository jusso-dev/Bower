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
        Assert.Contains($"tune(loadTextContent('rules/wec-brute-force.kql'), 'bower-wec-brute-force', detectionKeyScope, {Default("bruteForceThreshold")},", bicep, StringComparison.Ordinal);
        Assert.Contains($"tune(loadTextContent('rules/firewall-deny.kql'), 'bower-firewall-deny', detectionKeyScope, {Default("firewallDenyThreshold")},", bicep, StringComparison.Ordinal);
        // Detection keys and rule names are scoped per deployment.
        Assert.Contains("let ruleKey = \"bower-wec-brute-force:default\";", Read("rules", "wec-brute-force.kql"), StringComparison.Ordinal);
        Assert.Contains("let ruleKey = \"bower-firewall-deny:default\";", Read("rules", "firewall-deny.kql"), StringComparison.Ordinal);
        Assert.Contains("'let ruleKey = \"${rule}:default\";', 'let ruleKey = \"${rule}:${scope}\";'", bicep, StringComparison.Ordinal);
        Assert.Equal(3, Regex.Count(bicep, @"name: guid\(workspace\.id, 'bower-[a-z-]+', detectionKeyScope\)"));
        Assert.Contains("param detectionKeyScope string = 'default'", bicep, StringComparison.Ordinal);
        string tolerance = Read("rules", "beyond-tolerance.kql");
        Assert.Contains($"let maxDelay = {Default("maxIngestionDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains($"let settleDelay = {Default("settleDelayMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains($"let frequency = {Default("toleranceFrequencyMinutes")}m;", tolerance, StringComparison.Ordinal);
        Assert.Contains("'let frequency = 60m;', 'let frequency = ${toleranceFrequencyMinutes}m;'", bicep, StringComparison.Ordinal);
        Assert.Contains("queryFrequency: 'PT${toleranceFrequencyMinutes}M'", bicep, StringComparison.Ordinal);
        Assert.Contains("'let retrySpacing = 2;', 'let retrySpacing = ${spacing};'", bicep, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("wec-brute-force.kql")]
    [InlineData("firewall-deny.kql")]
    public void DetectionRules_RankOnlyBucketsThatReachTheThreshold(string file)
    {
        string query = Code(Read("rules", file));

        // Same candidate rows for counting and ranking; only buckets at or above the
        // threshold are joined back, and the final threshold filter is unchanged.
        Assert.Contains("let candidates = materialize(BowerSecurityEventsOfType(", query, StringComparison.Ordinal);
        Assert.Matches(@"let crossedBuckets = candidates\s*\|\s*summarize BucketEvents = count\(\) by SourceIpAddress, BucketStart\s*\|\s*where BucketEvents >= threshold", query);
        int join = query.IndexOf("candidates\n| join kind=inner crossedBuckets on SourceIpAddress, BucketStart", StringComparison.Ordinal);
        int sort = query.IndexOf("| sort by SourceIpAddress asc, BucketStart asc, BowerFirstIngested asc", StringComparison.Ordinal);
        Assert.True(join >= 0 && join < sort);
        Assert.Contains("| where DistinctEvents >= threshold", query, StringComparison.Ordinal);
        // Every filter on the events sits inside `candidates`, before the bucket count.
        string candidates = query[query.IndexOf("let candidates", StringComparison.Ordinal)..query.IndexOf("let crossedBuckets", StringComparison.Ordinal)];
        foreach (string filter in new[] { "isnotempty(SourceIpAddress)", "BowerFirstIngested < windowEnd", "<= maxDelay", "bin(BowerEventTime, bucketSize)" })
        {
            Assert.Contains(filter, candidates, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("wec-brute-force.kql")]
    [InlineData("firewall-deny.kql")]
    [InlineData("beyond-tolerance.kql")]
    public void Rules_AnchorWindowsToAFixedGrid(string file) =>
        Assert.Contains("let windowEnd = bin(now() - settleDelay, frequency);", Read("rules", file), StringComparison.Ordinal);

    [Fact]
    public void GridWindows_TileForEveryScheduleAndNeverPartlyOverlapAfterAShift()
    {
        // Mirrors `windowEnd = bin(now() - settleDelay, frequency)`, owned window
        // [windowEnd - frequency, windowEnd), for runs at any phase of the schedule.
        TimeSpan frequency = TimeSpan.FromMinutes(5), settle = TimeSpan.FromMinutes(5);
        DateTimeOffset origin = new(2026, 11, 2, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset End(DateTimeOffset now) =>
            new((now - settle).UtcTicks / frequency.Ticks * frequency.Ticks, TimeSpan.Zero);
        foreach (int phaseSeconds in new[] { 0, 1, 137, 299 })
        {
            DateTimeOffset previous = End(origin.AddSeconds(phaseSeconds));
            for (int run = 1; run < 50; run++)
            {
                DateTimeOffset end = End(origin.AddSeconds(phaseSeconds) + (run * frequency));
                Assert.Equal(previous + frequency, end); // contiguous, no gap, no overlap
                previous = end;
            }
        }

        // A schedule moved by any offset: each pair of windows is identical or disjoint.
        foreach (int shiftSeconds in new[] { 1, 59, 150, 299, 301, 977 })
        {
            DateTimeOffset before = End(origin.AddMinutes(7).AddSeconds(13));
            DateTimeOffset after = End(origin.AddMinutes(7).AddSeconds(13 + shiftSeconds));
            Assert.True(after == before || after - before >= frequency || before - after >= frequency);
        }
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
        int identities = typed.IndexOf("| join kind=leftsemi identities on CollectorId, EventId", StringComparison.Ordinal);
        int dropped = typed.IndexOf("project-away RawEnvelope", StringComparison.Ordinal);
        int collapse = typed.IndexOf("summarize arg_min", StringComparison.Ordinal);
        int typeFilter = typed.LastIndexOf("| where EventType in (eventTypes)", StringComparison.Ordinal);
        // Identities with a row of a listed type are collapsed over all their rows (any
        // type), so an EventId reused with another type picks the canonical winner; the
        // winners are filtered by type only after the collapse.
        Assert.True(dropped < identities && identities < collapse && collapse < typeFilter);
        // ingestion_time() is null on a join's output rows (found live): read it first.
        Assert.True(typed.IndexOf("BowerIngested = ingestion_time()", StringComparison.Ordinal) < identities);
        Assert.Contains("| where EventType in (eventTypes)\n    | distinct CollectorId, EventId;", typed, StringComparison.Ordinal);
        // The event time is read from RawEnvelope before it is dropped.
        Assert.True(typed.IndexOf("BowerEventTime = coalesce(todatetime(RawEnvelope.timeGenerated)", StringComparison.Ordinal) is >= 0 and var read && read < dropped);
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
        // The TimeGenerated look-back covers the oldest evaluated bucket of a catch-up run,
        // including the up-to-one-frequency offset of the grid-anchored window end.
        Assert.Contains(
            "var queryPeriodMinutes = maxIngestionDelayMinutes + bucketMinutes + catchUpMinutesChecked + settleDelayMinutes + frequencyMinutes + 10",
            bicep,
            StringComparison.Ordinal);
        // Azure Monitor rewrites event times older than two days; the tolerance stays below it.
        Assert.Contains("@maxValue(2820)\nparam maxIngestionDelayMinutes", bicep.ReplaceLineEndings("\n"), StringComparison.Ordinal);
    }

    /// <summary>The query without whole-line // comments.</summary>
    private static string Code(string kql) => string.Join('\n', kql.ReplaceLineEndings("\n").Split('\n')
        .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal))).Trim();
}
