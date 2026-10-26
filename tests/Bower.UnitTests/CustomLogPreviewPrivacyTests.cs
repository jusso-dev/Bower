using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Management.Api;
using Bower.Pipeline;
using Microsoft.AspNetCore.Builder;

namespace Bower.UnitTests;

/// <summary>
/// Adversarial tests for the server-owned preview privacy floor: submitted sensitivity
/// flags and mappings cannot reveal identity, IP or secret markers from a sample.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class CustomLogPreviewPrivacyTests
{
    private const string EmailMarker = "alex.marker@example.test";
    private const string UserMarker = "marker_alex";
    private const string IpMarker = "203.0.113.77";
    private const string AwsMarker = "AKIAMARKER0123456789";
    private const string JwtMarker =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtYXJrZXIifQ.c2lnbmF0dXJlbWFya2Vy";
    private const string FreeTextMarker = "marker-free-text-sentinel";

    private static readonly string[] Markers =
        [EmailMarker, UserMarker, IpMarker, AwsMarker, JwtMarker, FreeTextMarker];

    private static readonly string JsonSample =
        $$"""
        {"timestamp":"2026-07-29T10:00:00Z","severity":"warning","user":"{{UserMarker}}","email":"{{EmailMarker}}","source_ip":"{{IpMarker}}","action":"login","note":"{{FreeTextMarker}}","count":42}
        {"timestamp":"2026-07-29T10:01:00Z","severity":"{{AwsMarker}}","user":"{{UserMarker}}","email":"{{EmailMarker}}","source_ip":"{{IpMarker}}","action":"{{JwtMarker}}","note":"{{FreeTextMarker}}","count":7}
        """;

    // Every field claims to be non-sensitive and carries a mapping, which is exactly what
    // an operator could submit by hand.
    private static CustomLogParserConfiguration PermissiveJsonConfiguration() =>
        new(
            "1.0",
            CustomLogFormat.Json,
            [
                new CustomLogField("timestamp", CustomLogValueType.DateTime, "time", "TimeGenerated", false),
                new CustomLogField("severity", CustomLogValueType.Text, "severity", "EventSeverity", false),
                new CustomLogField("user", CustomLogValueType.Text, "activity_name", "EventType", false),
                new CustomLogField("email", CustomLogValueType.Text, "severity", "EventSeverity", false),
                new CustomLogField("source_ip", CustomLogValueType.IpAddress, "metadata.product.name", "EventProduct", false),
                new CustomLogField("action", CustomLogValueType.Text, "activity_name", "EventType", false),
                new CustomLogField("note", CustomLogValueType.Text, "metadata.product.name", "EventProduct", false),
                new CustomLogField("count", CustomLogValueType.WholeNumber, null, null, false)
            ]);

    [Fact]
    public void Preview_PastedSample_FlagsAndMappingsCannotExposeMarkers()
    {
        CustomLogPreviewResult preview = CustomLogParser.Preview(
            PermissiveJsonConfiguration(),
            JsonSample);

        Assert.True(preview.IsValid);
        AssertNoMarkers(JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson));
        IReadOnlyDictionary<string, CustomLogPreviewValue> first = preview.Rows[0].Fields;
        IReadOnlyDictionary<string, CustomLogPreviewValue> second = preview.Rows[1].Fields;
        Assert.True(first["user"].Redacted);
        Assert.True(first["email"].Redacted);
        Assert.Equal("[redacted:ip]", first["source_ip"].Value);
        Assert.True(first["note"].Redacted);
        Assert.True(second["severity"].Redacted);
        Assert.True(second["action"].Redacted);

        // Permitted non-sensitive fields still preview their values.
        Assert.Equal("login", first["action"].Value);
        Assert.False(first["action"].Redacted);
        Assert.Equal("warning", first["severity"].Value);
        Assert.Equal("2026-07-29T10:00:00Z", first["timestamp"].Value);
        Assert.Equal("42", first["count"].Value);
        Assert.False(first["count"].Redacted);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("severity", "EventSeverity")]
    [InlineData("activity_name", null)]
    [InlineData("x.y", "Anything")]
    public void Preview_UnknownTextStaysMaskedWhateverTheMapping(string? ocsf, string? asim)
    {
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.KeyValue,
            [
                new CustomLogField("detail", CustomLogValueType.Text, ocsf, asim, false),
                new CustomLogField("status", CustomLogValueType.Text, "status_detail", "EventResultDetails", false)
            ],
            KeyValueSeparator: "=");

        CustomLogPreviewResult preview = CustomLogParser.Preview(
            configuration,
            $"detail={FreeTextMarker} status=ok");

        Assert.True(preview.Rows[0].Fields["detail"].Redacted);
        Assert.Equal("ok", preview.Rows[0].Fields["status"].Value);
        AssertNoMarkers(JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson));
    }

    [Theory]
    [InlineData(EmailMarker)]
    [InlineData(IpMarker)]
    [InlineData(AwsMarker)]
    [InlineData(JwtMarker)]
    [InlineData("login user marker_alex from home")]
    public void Preview_DetectorsMaskPermittedFieldNames(string value)
    {
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.Csv,
            [
                new CustomLogField("action", CustomLogValueType.Text, "activity_name", "EventType", false),
                new CustomLogField("severity", CustomLogValueType.Text, "severity", "EventSeverity", false)
            ],
            Delimiter: ",");

        CustomLogPreviewResult preview = CustomLogParser.Preview(
            configuration,
            $"action,severity\n\"{value}\",INFO");

        Assert.True(preview.Rows[0].Fields["action"].Redacted);
        Assert.Equal("INFO", preview.Rows[0].Fields["severity"].Value);
        Assert.DoesNotContain(
            value,
            JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Preview_RegexCannotSliceSensitiveSpansIntoPermittedFields()
    {
        // Slicing an email and an IP into allow-listed names hides them from value-level
        // detectors; spans are checked against detections over the whole source line.
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.Regex,
            [
                new CustomLogField("action", CustomLogValueType.Text, "activity_name", "EventType", false),
                new CustomLogField("application", CustomLogValueType.Text, "metadata.product.name", "EventProduct", false),
                new CustomLogField("pid", CustomLogValueType.WholeNumber, "actor.process.pid", "ActorProcessId", false),
                new CustomLogField("severity", CustomLogValueType.Text, "severity", "EventSeverity", false),
                new CustomLogField("status", CustomLogValueType.Text, "status_detail", "EventResultDetails", false)
            ],
            Pattern: "^(?<action>[^@]+)@(?<application>\\S+)\\s+(?<pid>\\d+)\\.(?<severity>\\S+)\\s+(?<status>\\S+)$");

        CustomLogPreviewResult preview = CustomLogParser.Preview(
            configuration,
            $"{EmailMarker} {IpMarker} denied");

        Assert.True(preview.IsValid);
        IReadOnlyDictionary<string, CustomLogPreviewValue> fields = preview.Rows[0].Fields;
        Assert.True(fields["action"].Redacted);
        Assert.True(fields["application"].Redacted);
        Assert.True(fields["pid"].Redacted);
        Assert.True(fields["severity"].Redacted);
        Assert.Equal("denied", fields["status"].Value);
        string serialized = JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson);
        Assert.DoesNotContain("alex.marker", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("example.test", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("0.113.77", serialized, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("user_id")]
    [InlineData("client_ip")]
    [InlineData("account_number")]
    [InlineData("session_id")]
    [InlineData("phone")]
    public void Preview_SensitiveFieldNamesStayMaskedForTypedValues(string name)
    {
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.Json,
            [new CustomLogField(name, CustomLogValueType.WholeNumber, null, null, false)]);

        CustomLogPreviewResult preview = CustomLogParser.Preview(
            configuration,
            $$"""{"{{name}}":987654321}""");

        Assert.True(preview.Rows[0].Fields[name].Redacted);
        Assert.DoesNotContain(
            "987654321",
            JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Generate_CommonValuesStillPreview()
    {
        const string sample =
            """
            192.0.2.1 - alex [29/Jul/2026:10:00:00 +1000] "GET /admin HTTP/1.1" 403 120
            198.51.100.2 - casey [29/Jul/2026:10:00:01 +1000] "POST /login HTTP/1.1" 200 64
            """;
        const string severities =
            """
            2026-07-29T10:00:00Z CRITICAL disk failure on node
            2026-07-29T10:00:01Z WARNING retry scheduled
            """;

        IReadOnlyDictionary<string, CustomLogPreviewValue> access =
            CustomLogParser.Generate(sample).Preview.Rows[0].Fields;
        CustomLogPreviewResult levels = CustomLogParser.Generate(severities).Preview;

        Assert.Equal("GET", access["method"].Value);
        Assert.Equal("403", access["status"].Value);
        Assert.True(access["source_ip"].Redacted);
        Assert.True(access["identity"].Redacted);
        Assert.True(access["path"].Redacted);
        Assert.Equal("CRITICAL", levels.Rows[0].Fields["severity"].Value);
        Assert.Equal("WARNING", levels.Rows[1].Fields["severity"].Value);
        Assert.True(levels.Rows[0].Fields["message"].Redacted);
    }

    [Fact]
    public void Generate_PreviewAppliesTheSameFloor()
    {
        CustomLogGenerationResult result = CustomLogParser.Generate(JsonSample);

        AssertNoMarkers(JsonSerializer.Serialize(result.Preview, ManagementApiTests.ApiJson));
    }

    [Fact]
    public async Task Preview_ServerRootFixture_CannotExposeMarkers()
    {
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "security.jsonl");
        await File.WriteAllTextAsync(path, JsonSample, TestContext.Current.CancellationToken);

        string sample = await CustomLogSampleReader.ReadAsync(
            new CustomLogInput(null, path),
            root.Path,
            TestContext.Current.CancellationToken);
        CustomLogPreviewResult preview = CustomLogParser.Preview(PermissiveJsonConfiguration(), sample);

        Assert.True(preview.IsValid);
        AssertNoMarkers(JsonSerializer.Serialize(preview, ManagementApiTests.ApiJson));
        Assert.Equal("login", preview.Rows[0].Fields["action"].Value);
    }

    [Fact]
    public async Task PreviewEndpoint_ServerRootFixture_ResponsesAndErrorsContainNoMarkers()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "security.jsonl");
        await File.WriteAllTextAsync(path, JsonSample, cancellationToken);
        string? previousRoots = Environment.GetEnvironmentVariable("BOWER_CUSTOM_LOG_ROOTS");
        Environment.SetEnvironmentVariable("BOWER_CUSTOM_LOG_ROOTS", root.Path);
        try
        {
            await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);
            HttpClient operatorClient = ManagementApiTests.Client(app, BowerRoles.Operator);

            // Every field toggled to non-sensitive with arbitrary mappings.
            using HttpResponseMessage response = await PostPreviewAsync(
                operatorClient,
                path,
                PermissiveJsonConfiguration(),
                cancellationToken);
            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertNoMarkers(body);
            CustomLogPreviewResult? preview = JsonSerializer.Deserialize<CustomLogPreviewResult>(
                body,
                ManagementApiTests.ApiJson);
            Assert.Equal("login", preview!.Rows[0].Fields["action"].Value);

            // Parser mismatch and invalid configuration: issues stay metadata-only.
            CustomLogParserConfiguration[] failing =
            [
                PermissiveJsonConfiguration() with { Format = CustomLogFormat.Csv, Delimiter = "," },
                PermissiveJsonConfiguration() with
                {
                    Format = CustomLogFormat.Regex,
                    Pattern = "^(?<timestamp>x)(?<severity>x)(?<user>x)(?<email>x)(?<source_ip>x)(?<action>x)(?<note>x)(?<count>x)$"
                },
                PermissiveJsonConfiguration() with { Version = "2.0" }
            ];
            foreach (CustomLogParserConfiguration configuration in failing)
            {
                using HttpResponseMessage failure = await PostPreviewAsync(
                    operatorClient,
                    path,
                    configuration,
                    cancellationToken);
                string failureBody = await failure.Content.ReadAsStringAsync(cancellationToken);
                Assert.Equal(HttpStatusCode.OK, failure.StatusCode);
                Assert.Contains("\"isValid\":false", failureBody, StringComparison.Ordinal);
                AssertNoMarkers(failureBody);
            }

            // Root restriction and authorization are unchanged.
            using HttpResponseMessage outside = await PostPreviewAsync(
                operatorClient,
                Path.Combine(directory.Path, "management.db"),
                PermissiveJsonConfiguration(),
                cancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, outside.StatusCode);
            AssertNoMarkers(await outside.Content.ReadAsStringAsync(cancellationToken));

            using HttpResponseMessage viewer = await PostPreviewAsync(
                ManagementApiTests.Client(app, BowerRoles.Viewer),
                path,
                PermissiveJsonConfiguration(),
                cancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, viewer.StatusCode);
            using HttpResponseMessage anonymous = await PostPreviewAsync(
                ManagementApiTests.Client(app, string.Empty),
                path,
                PermissiveJsonConfiguration(),
                cancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("BOWER_CUSTOM_LOG_ROOTS", previousRoots);
        }
    }

    private static Task<HttpResponseMessage> PostPreviewAsync(
        HttpClient client,
        string path,
        CustomLogParserConfiguration configuration,
        CancellationToken cancellationToken) =>
        client.PostAsJsonAsync(
            "/api/custom-logs/preview",
            new CustomLogPreviewRequest(new CustomLogInput(null, path), configuration),
            ManagementApiTests.ApiJson,
            cancellationToken);

    private static void AssertNoMarkers(string text)
    {
        foreach (string marker in Markers)
        {
            Assert.DoesNotContain(marker, text, StringComparison.Ordinal);
        }
    }
}
