using Bower.Management.Api;
using Bower.Pipeline;

namespace Bower.UnitTests;

public sealed class CustomLogParserTests
{
    [Fact]
    public void Generate_JsonLines_InfersSecurityMappingsAndRedactsPreview()
    {
        const string sample =
            """
            {"timestamp":"2026-07-29T10:00:00Z","severity":"warning","user":"alex@example.test","source_ip":"192.0.2.10","action":"login","token":"must-not-appear"}
            {"timestamp":"2026-07-29T10:01:00Z","severity":"error","user":"casey@example.test","source_ip":"198.51.100.4","action":"login"}
            """;

        CustomLogGenerationResult result = CustomLogParser.Generate(sample);

        Assert.Equal(CustomLogFormat.Json, result.Format);
        Assert.Equal(1, result.Confidence);
        Assert.DoesNotContain(
            result.Configuration.Fields,
            field => field.SourceName == "token");
        Assert.Contains(
            result.Configuration.Fields,
            field => field is
            {
                SourceName: "timestamp",
                Type: CustomLogValueType.DateTime,
                OcsfPath: "time",
                AsimField: "TimeGenerated"
            });
        Assert.Contains(
            result.Configuration.Fields,
            field => field is
            {
                SourceName: "source_ip",
                Type: CustomLogValueType.IpAddress,
                OcsfPath: "src_endpoint.ip",
                AsimField: "SrcIpAddr",
                Sensitive: true
            });
        Assert.True(result.Preview.IsValid);
        Assert.Equal("[redacted]", result.Preview.Rows[0].Fields["user"].Value);
        Assert.Equal("[redacted:ip]", result.Preview.Rows[0].Fields["source_ip"].Value);
        Assert.Contains(
            result.Tests,
            test => test.Name == "rejects malformed record" && !test.ShouldParse);
    }

    [Fact]
    public void Generate_Csv_UsesHeaderAndStableColumnCount()
    {
        const string sample =
            """
            timestamp,severity,username,src_ip,action
            2026-07-29T10:00:00Z,INFO,alex,192.0.2.1,read
            2026-07-29T10:01:00Z,ERROR,casey,192.0.2.2,delete
            """;

        CustomLogGenerationResult result = CustomLogParser.Generate(sample);

        Assert.Equal(CustomLogFormat.Csv, result.Format);
        Assert.Equal(",", result.Configuration.Delimiter);
        Assert.Equal(5, result.Schema.Fields.Count);
        Assert.All(result.Schema.Fields, field => Assert.True(field.Required));
    }

    [Fact]
    public void Generate_KeyValue_HandlesQuotedValues()
    {
        const string sample =
            """
            timestamp=2026-07-29T10:00:00Z severity=INFO user="Alex Lee" action=login
            timestamp=2026-07-29T10:01:00Z severity=ERROR user="Casey Li" action=logout
            """;

        CustomLogGenerationResult result = CustomLogParser.Generate(sample);

        Assert.Equal(CustomLogFormat.KeyValue, result.Format);
        Assert.Equal("=", result.Configuration.KeyValueSeparator);
        Assert.Equal("[redacted]", result.Preview.Rows[0].Fields["user"].Value);
    }

    [Fact]
    public void Generate_CommonLog_ProducesSafeRegexConfiguration()
    {
        const string sample =
            """
            192.0.2.1 - alex [29/Jul/2026:10:00:00 +1000] "GET /admin HTTP/1.1" 403 120
            198.51.100.2 - casey [29/Jul/2026:10:00:01 +1000] "POST /login HTTP/1.1" 200 64
            """;

        CustomLogGenerationResult result = CustomLogParser.Generate(sample);

        Assert.Equal(CustomLogFormat.Regex, result.Format);
        Assert.NotNull(result.Configuration.Pattern);
        Assert.Contains(
            result.Configuration.Fields,
            field => field.SourceName == "method" && field.OcsfPath == "activity_name");
        Assert.True(result.Preview.IsValid);
    }

    [Fact]
    public void Preview_RejectsUnsupportedRegexConstruct()
    {
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.Regex,
            [new CustomLogField("value", CustomLogValueType.Text, null, null, true)],
            Pattern: "^(?=x)(?<value>.*)$");

        CustomLogPreviewResult preview = CustomLogParser.Preview(configuration, "x");

        Assert.False(preview.IsValid);
        Assert.Contains(
            preview.Issues,
            issue => issue.Contains("non-backtracking", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SampleReader_AllowsOnlyConfiguredRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), $"bower-custom-log-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            string samplePath = Path.Combine(root, "sample.log");
            await File.WriteAllTextAsync(
                samplePath,
                """{"severity":"INFO"}""",
                TestContext.Current.CancellationToken);

            string sample = await CustomLogSampleReader.ReadAsync(
                new CustomLogInput(null, samplePath),
                root,
                TestContext.Current.CancellationToken);

            Assert.Contains("severity", sample, StringComparison.Ordinal);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                CustomLogSampleReader.ReadAsync(
                    new CustomLogInput(null, Path.Combine(Path.GetTempPath(), "outside.log")),
                    root,
                    TestContext.Current.CancellationToken));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SampleReader_RejectsAmbiguousInput()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            CustomLogSampleReader.ReadAsync(
                new CustomLogInput("sample", "/tmp/sample.log"),
                null,
                TestContext.Current.CancellationToken));
    }
}
