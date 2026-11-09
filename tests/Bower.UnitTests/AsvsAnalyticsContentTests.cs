using System.Text.RegularExpressions;
using Bower.Dcr;

namespace Bower.UnitTests;

/// <summary>
/// Static checks for deploy/sentinel/analytics/rules/asvs and asvs.bicep. They do not run
/// Kusto; they hold the replay-safety and schema contract of the existing rules
/// (<see cref="SentinelAnalyticsContentTests"/>) for the ASVS starter content.
/// </summary>
public sealed partial class AsvsAnalyticsContentTests
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "deploy", "sentinel", "analytics");

    public static TheoryData<string, string> Rules => new()
    {
        { "password-spray.kql", "bower-asvs-password-spray" },
        { "privilege-change.kql", "bower-asvs-privilege-change" },
        { "admin-after-hours.kql", "bower-asvs-admin-after-hours" },
        { "mass-export.kql", "bower-asvs-mass-export" },
        { "log-silence.kql", "bower-asvs-log-silence" },
    };

    // Names the rules compute themselves; anything else with a column prefix must be a column.
    private static readonly HashSet<string> RuleLocals = new(["Applications", "Collectors", "Events"], StringComparer.Ordinal);

    private static string Read(params string[] path) => File.ReadAllText(Path.Combine([Root, .. path]));

    private static string Code(string query) =>
        string.Join('\n', query.ReplaceLineEndings("\n").Split('\n').Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal)));

    [Theory]
    [MemberData(nameof(Rules))]
    public void Rules_AlertOncePerDetectionKeyAndUseOnlyTableColumns(string file, string rule)
    {
        string query = Code(Read("rules", "asvs", file));
        HashSet<string> columns = SentinelSchema.Default.TableColumns.Select(column => column.Name).ToHashSet(StringComparer.Ordinal);

        Assert.Contains($"let ruleKey = \"{rule}:default\";", query, StringComparison.Ordinal);
        Assert.Contains("BowerDetectionKey !in (alerted)", query, StringComparison.Ordinal);
        Assert.Contains("| project BowerDetectionKey,", query, StringComparison.Ordinal);
        // dcount() is an estimate: alert gates count exactly.
        Assert.DoesNotContain("dcount(", query, StringComparison.Ordinal);
        foreach (Match match in ColumnReference().Matches(query))
        {
            string name = match.Groups["column"].Value;
            if (KnownColumn().IsMatch(name) && !RuleLocals.Contains(name))
            {
                Assert.Contains(name, columns);
            }
        }
    }

    [Theory]
    [InlineData("password-spray.kql")]
    [InlineData("privilege-change.kql")]
    [InlineData("admin-after-hours.kql")]
    [InlineData("mass-export.kql")]
    public void EventRules_ReadTheReplayCollapsedParserAndBoundLateEvents(string file)
    {
        string query = Code(Read("rules", "asvs", file));

        Assert.Matches(@"BowerSecurityEventsOfType\(dynamic\(\[""[a-z_]+""(, ""[a-z_]+"")*\]\)\)", query);
        Assert.Contains("let windowEnd = bin(now() - settleDelay, frequency);", query, StringComparison.Ordinal);
        Assert.Contains("BowerFirstIngested - BowerEventTime <= maxDelay", query, StringComparison.Ordinal);
        Assert.DoesNotContain("ingestion_time()", query, StringComparison.Ordinal);
    }

    [Fact]
    public void Rules_CiteOnlyEventTypesThePackOrDefaultsSelect()
    {
        string[] selected =
        [
            "authentication_failure", "authentication_success", "role_membership_changed", "permission_changed",
            "admin_action", "configuration_changed", "sensitive_data_exported", "sensitive_data_accessed"
        ];
        foreach (string file in Directory.GetFiles(Path.Combine(Root, "rules", "asvs"), "*.kql"))
        {
            foreach (Match list in TypeList().Matches(Code(File.ReadAllText(file))))
            {
                foreach (Match type in Regex.Matches(list.Value, @"""([a-z_]+)"""))
                {
                    Assert.Contains(type.Groups[1].Value, selected);
                }
            }
        }
    }

    [Fact]
    public void AfterHours_DefaultsToSydneyAndIsParameterised()
    {
        string query = Read("rules", "asvs", "admin-after-hours.kql");
        string bicep = Read("asvs.bicep");

        Assert.Contains("let timeZone = \"Australia/Sydney\";", query, StringComparison.Ordinal);
        Assert.Contains("datetime_utc_to_local(BowerEventTime, timeZone)", query, StringComparison.Ordinal);
        Assert.Contains("param timeZone string = 'Australia/Sydney'", bicep, StringComparison.Ordinal);
        Assert.Contains("'let timeZone = \"Australia/Sydney\";', 'let timeZone = \"${timeZone}\";'", bicep, StringComparison.Ordinal);
        Assert.Contains("'let businessStart = 7;'", bicep, StringComparison.Ordinal);
        Assert.Contains("'let businessEnd = 19;'", bicep, StringComparison.Ordinal);
        Assert.Contains("let businessStart = 7;", query, StringComparison.Ordinal);
        Assert.Contains("let businessEnd = 19;", query, StringComparison.Ordinal);
    }

    [Fact]
    public void Bicep_IsDisabledByDefaultAndEveryReplaceAnchorExists()
    {
        string bicep = Read("asvs.bicep");

        Assert.Contains("param enableRules bool = false", bicep, StringComparison.Ordinal);
        Assert.Contains("enabled: enableRules", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft.OperationalInsights/workspaces/tables", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("dataCollectionRules", bicep, StringComparison.Ordinal);
        // Every replace() anchor names a line that exists in the rule file, or the
        // parameter would silently keep the default.
        foreach (Match anchor in Anchor().Matches(bicep))
        {
            string line = anchor.Groups["line"].Value.Replace("${rule}", "RULE", StringComparison.Ordinal);
            if (line.Contains("RULE", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.True(
                Directory.GetFiles(Path.Combine(Root, "rules", "asvs"), "*.kql").Any(file => File.ReadAllText(file).Contains(line, StringComparison.Ordinal)),
                $"Missing anchor: {line}");
        }

        foreach ((string file, string rule) in new[]
        {
            ("password-spray", "bower-asvs-password-spray"), ("privilege-change", "bower-asvs-privilege-change"),
            ("admin-after-hours", "bower-asvs-admin-after-hours"), ("mass-export", "bower-asvs-mass-export"),
            ("log-silence", "bower-asvs-log-silence"),
        })
        {
            Assert.Contains($"loadTextContent('rules/asvs/{file}.kql'), '{rule}', detectionKeyScope)", bicep, StringComparison.Ordinal);
            Assert.Contains($"key: '{rule}'", bicep, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Bicep_ThresholdDefaultsMatchTheRuleFiles()
    {
        string bicep = Read("asvs.bicep");
        int Default(string name) => int.Parse(Regex.Match(bicep, $@"param {name} int = (?<value>\d+)").Groups["value"].Value, System.Globalization.CultureInfo.InvariantCulture);

        Assert.Contains($"let accountThreshold = {Default("sprayAccountThreshold")};", Read("rules", "asvs", "password-spray.kql"), StringComparison.Ordinal);
        Assert.Contains($"let recordThreshold = {Default("exportRecordThreshold")};", Read("rules", "asvs", "mass-export.kql"), StringComparison.Ordinal);
        Assert.Contains($"let exportThreshold = {Default("exportCountThreshold")};", Read("rules", "asvs", "mass-export.kql"), StringComparison.Ordinal);
        Assert.Contains($"let silence = {Default("silenceMinutes")}m;", Read("rules", "asvs", "log-silence.kql"), StringComparison.Ordinal);
    }

    [GeneratedRegex(@"\b(?<column>[A-Z][A-Za-z]+)\b")]
    private static partial Regex ColumnReference();

    // Table columns the rules may use; other capitalised words are KQL names or locals.
    [GeneratedRegex(@"^(Event[A-Z]\w*|Application\w*|Actor\w+|Source\w+|Correlation\w+|Collector\w+|Attributes|Labels|Target|Change|RawEnvelope|TimeGenerated)$")]
    private static partial Regex KnownColumn();

    [GeneratedRegex(@"(BowerSecurityEventsOfType\(dynamic\(\[[^\]]*\]\)\)|EventType in \([^)]*\))")]
    private static partial Regex TypeList();

    [GeneratedRegex(@"'(?<line>let [A-Za-z]+ = [^']+;)', '")]
    private static partial Regex Anchor();
}
