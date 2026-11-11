using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Dcr;
using Bower.Output.AmaSyslog;
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
    public void AmaSyslogRule_IsGeneratedFromTheSchemaModel()
    {
        // #236: one definition. Adding a column to SentinelSchema changes both rules or fails here.
        string syslog = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "ama-syslog-dcr.bicep"));
        string expected = SentinelSchema.Default.SyslogTransformKql(AmaSyslogOutput.MessagePrefix, new AmaSyslogOutputOptions { Id = "ama-syslog" }.AppName);

        Assert.True(
            Normalise(expected) == Normalise(Transform(syslog)),
            "deploy/bicep/ama-syslog-dcr.bicep transformKql differs from SentinelSchema.SyslogTransformKql. Regenerate it:\n" + expected);
        Assert.Contains("outputStream: 'Custom-BowerSecurity_CL'", syslog, StringComparison.Ordinal);
        Assert.Contains("streams: ['Microsoft-Syslog']", syslog, StringComparison.Ordinal);
        Assert.Contains("param facility string = 'local4'", syslog, StringComparison.Ordinal);
        // Notice and above: Bower writes at notice, so a lower minimum would only add noise.
        Assert.Contains("logLevels: ['Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']", syslog, StringComparison.Ordinal);
    }

    [Fact]
    public void AmaSyslogRule_ProjectsTheSameColumnsAsTheIngestionRule()
    {
        // The generated projection reads each main.bicep column from the decoded envelope e.
        string main = Normalise(Transform(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"))));
        string syslog = Normalise(SentinelSchema.Default.SyslogTransformKql(AmaSyslogOutput.MessagePrefix, "bower"));
        string[] Columns(string kql) => [.. Regex.Matches(kql.Split("| project ", 2)[1], @"(?:^|, )(?<name>\w+) = ").Select(match => match.Groups["name"].Value)];

        Assert.Equal(Columns(main), Columns(syslog));
        Assert.Equal(SentinelSchema.Default.TableColumns.Select(column => column.Name), Columns(syslog));
        Assert.Contains("TimeGenerated = todatetime(e.timeGenerated)", syslog, StringComparison.Ordinal);
        Assert.Contains("RawEnvelope = e,", syslog, StringComparison.Ordinal);
        Assert.Contains("ActorUsername = substring(tostring(e.actor.username), 0, 256)", syslog, StringComparison.Ordinal);
        Assert.DoesNotContain("tostring(eventId)", syslog, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("bower-b64:eyJhIjoxfQ==", true)]
    [InlineData("  bower-b64:eyJhIjoxfQ==\n", true)]
    [InlineData("bower-b64:eyJhIjoxfQ== trailing", false)]
    [InlineData("prefix bower-b64:eyJhIjoxfQ==", false)]
    [InlineData("bower-b64:eyJhIjo", true)]
    [InlineData("bower-b64:", false)]
    public void AmaSyslogRule_DecodesOnlyAMessageThatIsTheMarkerAndOneBase64Value(string message, bool kept)
    {
        // The extract pattern, read with .NET's regex engine, which matches RE2 for this pattern.
        // Whether Azure accepts and runs it the same way is check 1 of the live run (#249).
        string transform = SentinelSchema.Default.SyslogTransformKql(AmaSyslogOutput.MessagePrefix, "bower");
        string pattern = Regex.Match(transform, "extract\\(@\"(?<pattern>[^\"]+)\"").Groups["pattern"].Value;

        Assert.Equal(kept, Regex.IsMatch(message, pattern.Replace("$", @"\n?\z", StringComparison.Ordinal)));
    }

    [Fact]
    public void AmaSyslogRule_SendsWhatItCannotDecodeToTheSyslogTable()
    {
        // #231: the second data flow is generated too, and keeps a bower message out of
        // BowerSecurity_CL only by putting it in Syslog.
        string syslog = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "ama-syslog-dcr.bicep"));
        string[] transforms = [.. Regex.Matches(syslog, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Select(match => match.Groups["kql"].Value)];
        string expected = SentinelSchema.Default.SyslogUndecodedTransformKql(AmaSyslogOutput.MessagePrefix, new AmaSyslogOutputOptions { Id = "ama-syslog" }.AppName);

        Assert.Equal(2, transforms.Length);
        Assert.True(
            Normalise(expected) == Normalise(transforms[1]),
            "deploy/bicep/ama-syslog-dcr.bicep second transformKql differs from SentinelSchema.SyslogUndecodedTransformKql. Regenerate it:\n" + expected);
        Assert.Contains("outputStream: 'Microsoft-Syslog'", syslog, StringComparison.Ordinal);
        Assert.Contains("param keepUndecodedInSyslog bool = true", syslog, StringComparison.Ordinal);
        // Same pattern and schema filter as the first flow, negated, so no message lands in both.
        string decode = SentinelSchema.Default.SyslogTransformKql(AmaSyslogOutput.MessagePrefix, "bower");
        string Pattern(string kql) => Regex.Match(kql, "extract\\(@\"(?<pattern>[^\"]+)\"").Groups["pattern"].Value;
        Assert.Equal(Pattern(decode), Pattern(expected));
        Assert.Contains("| where tostring(e.schemaVersion) == \"1.0.0\"", decode, StringComparison.Ordinal);
        Assert.Contains("| where isempty(b64) or v != \"1.0.0\"", expected, StringComparison.Ordinal);
    }

    [Fact]
    public void AmaSyslogOutputDefaults_MatchTheRule()
    {
        AmaSyslogOutputOptions options = new() { Id = "ama-syslog" };

        Assert.Equal((20, 5, "/dev/log"), (options.Facility, options.Severity, options.SocketPath));
    }

    [Fact]
    public async Task EmitEventScript_AppendsALineThatMatchesTheEnvelopeSchema()
    {
        string? python = FindOnPath(OperatingSystem.IsWindows() ? "python3.exe" : "python3");
        Assert.SkipWhen(python is null, "python3 is not on PATH.");
        string directory = Directory.CreateTempSubdirectory("bower-emit-").FullName;
        try
        {
            string target = Path.Combine(directory, "events.jsonl");
            // A fragment left by a cut-short writer: the script must start its event on a new line.
            await File.WriteAllTextAsync(target, "{\"schemaVersion\":\"1.0.0\",\"eventId\":\"cut-sh", TestContext.Current.CancellationToken);

            await RunEmitEvent(python!, target, "--application", "billing-api", "--environment", "staging");
            await RunEmitEvent(python!, target);

            string[] lines = (await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken)).Split('\n');
            Assert.Equal(4, lines.Length);
            Assert.Equal("", lines[^1]);
            using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "schemas", "envelope", "security-event.schema.json")));
            foreach (string line in lines[1..^1])
            {
                using JsonDocument written = JsonDocument.Parse(line);
                List<string> errors = [];
                AsvsExampleContractTests.Validate(written.RootElement, schema.RootElement, schema.RootElement, "$", errors);
                Assert.True(errors.Count == 0, string.Join("; ", errors));
                Assert.Equal(line, FirehoseLogObjectReader.TryExtractEnvelope(line));
            }

            using JsonDocument first = JsonDocument.Parse(lines[1]);
            Assert.Equal("billing-api", first.RootElement.GetProperty("application").GetProperty("name").GetString());
            Assert.Equal("staging", first.RootElement.GetProperty("application").GetProperty("environment").GetString());
            using JsonDocument second = JsonDocument.Parse(lines[2]);
            Assert.Equal("orders-api", second.RootElement.GetProperty("application").GetProperty("name").GetString());
            Assert.NotEqual(first.RootElement.GetProperty("eventId").GetString(), second.RootElement.GetProperty("eventId").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task RunEmitEvent(string python, params string[] arguments)
    {
        System.Diagnostics.ProcessStartInfo start = new(python)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in (string[])["-I", Path.Combine(Examples, "emit_event.py"), .. arguments])
        {
            start.ArgumentList.Add(argument);
        }

        using System.Diagnostics.Process process = System.Diagnostics.Process.Start(start)!;
        Task<string> output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        string error = await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.True(process.ExitCode == 0, $"emit_event.py exited {process.ExitCode}: {error}");
        Assert.StartsWith("appended event ", await output, StringComparison.Ordinal);
    }

    private static string? FindOnPath(string executable) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, executable))
            .FirstOrDefault(File.Exists);

    private static string Transform(string bicep) =>
        Regex.Match(bicep, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Groups["kql"].Value;

    private static string Normalise(string kql) => Regex.Replace(kql, @"\s+", " ").Trim();
}
