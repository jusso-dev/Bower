using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Signed pack transforms: placement before redaction, sensitivity, quarantine and determinism.</summary>
[Collection(SerialHostTests.Name)]
public sealed class TransformPackTests
{
    private const string Token = "transform-pack-test-token-0123456789abcdef";
    private const string Endpoint = "/v1/packs/linux-journald-ssh/parsers/0/events";
    private const string Message = "Failed password for invalid user deploy-admin from 203.0.113.5 port 52144 ssh2";
    private static readonly DateTimeOffset At = new(2026, 10, 26, 1, 2, 3, TimeSpan.Zero);
    private static string Source => Path.Combine(AppContext.BaseDirectory, "packs", "linux-journald-ssh");

    private static string Raw(string message = Message, DateTimeOffset? time = null) => new JsonObject
    {
        ["__CURSOR"] = "s=7a1c;i=1f01;b=55aa;m=91;t=63e2;x=c3",
        ["__REALTIME_TIMESTAMP"] = (((time ?? At).UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["SYSLOG_IDENTIFIER"] = "sshd",
        ["_HOSTNAME"] = "bastion-1",
        ["MESSAGE"] = message
    }.ToJsonString();

    private static LoadedPack BuildPack(string source, TemporaryDirectory directory)
    {
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        return PackArchive.Load(PackArchive.Build(source, privatePem, directory.Path), [publicPem]);
    }

    private static string CopyPack(TemporaryDirectory directory)
    {
        string target = Path.Combine(directory.Path, "source");
        foreach (string file in Directory.EnumerateFiles(Source, "*", SearchOption.AllDirectories))
        {
            string destination = Path.Combine(target, Path.GetRelativePath(Source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination);
        }

        return target;
    }

    private static void EditTransforms(string source, Action<JsonArray> edit)
    {
        string path = Path.Combine(source, "parsers", "sshd-journald.json");
        JsonObject parser = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        edit(parser["runtime"]!["transforms"]!.AsArray());
        File.WriteAllText(path, parser.ToJsonString());
    }

    [Fact]
    public void JournaldPack_SignsAndEverySamplePasses_IncludingTransformQuarantine()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = BuildPack(Source, directory);
        Assert.NotNull(pack.Parsers[0].Runtime!.Transforms);
        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));
        Assert.All(results, result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
        Assert.Contains(results, result => result.ActualDecision == "quarantine");
        Assert.Contains(results, result => result.ActualDecision == "redactandaccept");
    }

    [Fact]
    public void Transform_RunsBeforeMapping_AndIsByteForByteDeterministic()
    {
        using TemporaryDirectory directory = new();
        CustomLogParserConfiguration parser = BuildPack(Source, directory).Parsers[0];
        SecurityEventEnvelope first = PackRuntime.Parse(parser, Raw(), At)!;
        // Pre-redaction envelope inside the collector: the transform extracted these from MESSAGE.
        Assert.Equal("deploy-admin", first.Actor!.Username);
        Assert.Equal("203.0.113.5", first.Source!.IpAddress);
        Assert.Equal("InvalidCredentials", first.EventOutcomeReason);
        Assert.Equal(new DateTimeOffset(2026, 10, 26, 1, 2, 3, TimeSpan.Zero), first.TimeGenerated);
        Assert.Null(first.Security);
        Assert.Null(first.Attributes);
        Assert.Null(first.Labels);
        string serialized = JsonSerializer.Serialize(first, BowerJson.Envelope);
        Assert.DoesNotContain("bastion-1", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Failed password", serialized, StringComparison.Ordinal);
        // Byte-identical envelope pinned for the Rust port (bower-packs transform_pack_tests);
        // set BOWER_PACK_ENVELOPE_OUTPUT to a file path to regenerate.
        if (Environment.GetEnvironmentVariable("BOWER_PACK_ENVELOPE_OUTPUT") is { Length: > 0 } output)
        {
            File.WriteAllText(output, serialized);
        }

        Assert.Equal(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "pack-vectors", "transform-journald-ssh.json")),
            serialized);
        for (int run = 0; run < 3; run++)
        {
            Assert.Equal(serialized, JsonSerializer.Serialize(PackRuntime.Parse(parser, Raw(), At)!, BowerJson.Envelope));
        }
    }

    [Fact]
    public void Transform_CannotSetTheSecurityDecisionOrLaunderSensitiveFields()
    {
        string[][] attacks =
        [
            [".\"security.decision\" = \"accept\""],
            [".security = \"accept\""],
            [".bowerDetections = \"forged\""],
            [".result = \"failure\"", "del(.MESSAGE)"],
            ["rename(.MESSAGE, .note)"],
            [".__CURSOR = .MESSAGE"],
            ["if contains(.MESSAGE, \"x\") { .SYSLOG_IDENTIFIER = \"sshd\" }"],
            [".password = .MESSAGE"],
            [".x = .token"]
        ];
        string[] codes =
        [
            TransformErrorCodes.InvalidTarget, TransformErrorCodes.InvalidTarget, TransformErrorCodes.InvalidTarget,
            TransformErrorCodes.SensitiveField, TransformErrorCodes.SensitiveField, TransformErrorCodes.SensitiveFlow,
            TransformErrorCodes.SensitiveFlow, TransformErrorCodes.InvalidTarget, TransformErrorCodes.ProhibitedField
        ];
        for (int index = 0; index < attacks.Length; index++)
        {
            using TemporaryDirectory copy = new();
            string copied = CopyPack(copy);
            EditTransforms(copied, transforms =>
            {
                foreach (string statement in attacks[index])
                {
                    transforms.Add(statement);
                }
            });
            (string privateKey, _, _) = DetachedSigner.GenerateKeyPair();
            InvalidDataException failure = Assert.Throws<InvalidDataException>(
                () => PackArchive.Build(copied, privateKey, Path.Combine(copy.Path, "out")));
            Assert.Contains(codes[index], failure.Message, StringComparison.Ordinal);
            Assert.False(Directory.Exists(Path.Combine(copy.Path, "out")));
        }
    }

    [Fact]
    public void Errors_AreMetadataOnly()
    {
        CustomLogField[] fields = [new("note", CustomLogValueType.Text, null, null, true)];
        TransformIssue issue = Assert.Single(TransformProgram.Validate(
            new TransformDefinition([".a = concat(\"SECRET-LITERAL-1\", "], null, fields)));
        Assert.Equal(TransformErrorCodes.Syntax, issue.Code);
        Assert.DoesNotContain("SECRET", issue.ToString(), StringComparison.Ordinal);
        TransformProgram program = TransformProgram.Compile(new TransformDefinition([".a = lower(.note)"], null, fields));
        TransformException failure = Assert.Throws<TransformException>(
            () => program.Execute("""{"note":["SECRET-VALUE-2"]}""", At));
        Assert.Equal(TransformErrorCodes.TypeError, failure.Message);
        Assert.Equal(failure.Code, failure.Message);
    }

    [Fact]
    public void Preview_ValidatesButNeverRunsTransforms()
    {
        CustomLogParserConfiguration Configuration(params string[] transforms) => new(
            "1.0",
            CustomLogFormat.Json,
            [
                new("id", CustomLogValueType.Text, "metadata.uid", null, false),
                new("timestamp", CustomLogValueType.DateTime, "time", "TimeGenerated", false),
                new("severity", CustomLogValueType.Text, "severity", "EventSeverity", false)
            ],
            Runtime: new CustomLogRuntimeMapping(
                "app", "production", "authentication", "authentication_failure", "authentication.attempt", "failure",
                new Dictionary<string, string> { ["severity"] = "warning" },
                new Dictionary<string, string> { ["eventId"] = "id", ["timeGenerated"] = "timestamp" },
                transforms));
        const string sample = """{"id":"a1","timestamp":"2026-10-26T01:02:03Z","severity":"warning"}""";

        CustomLogPreviewResult preview = CustomLogParser.Preview(Configuration(".severity = upper(.severity)"), sample);
        Assert.True(preview.IsValid, string.Join(" ", preview.Issues));
        Assert.Equal("warning", Assert.Single(preview.Rows).Fields["severity"].Value);

        CustomLogPreviewResult invalid = CustomLogParser.Preview(Configuration(".severity = \"SECRET-LITERAL\" +"), sample);
        Assert.False(invalid.IsValid);
        Assert.Equal("Transform statement 1 column 30: transform-syntax.", Assert.Single(invalid.Issues));
        Assert.Empty(invalid.Rows);
    }

    [Fact]
    public void ParserWithoutTransforms_IsUnchanged()
    {
        using TemporaryDirectory directory = new();
        CustomLogParserConfiguration parser = BuildPack(
            Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway"), directory).Parsers[0];
        Assert.Null(parser.Runtime!.ToTransformDefinition(parser.Fields));
        Assert.Empty(CustomLogParser.ValidateConfiguration(parser));
    }

    [Fact]
    public async Task Collector_QuarantinesBudgetOverrunWithoutPersisting_AndCountsTheTransformStage()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string source = CopyPack(directory);
        EditTransforms(source, transforms => transforms.Insert(0, ".slow = regex_match(.MESSAGE, '(?:a?){100}a{100}$')"));
        await using WebApplication app = await Start(source, directory, cancellation);
        using HttpClient client = app.GetTestClient();

        string pathological = new string('a', 5000) + "b deploy-admin";
        using HttpResponseMessage quarantined = await Send(client, Raw(pathological, DateTimeOffset.UtcNow), cancellation);
        Assert.Equal(HttpStatusCode.BadRequest, quarantined.StatusCode);
        string body = await quarantined.Content.ReadAsStringAsync(cancellation);
        Assert.Equal(
            """{"eventId":null,"decision":"quarantine","queued":false,"duplicate":false,"reasons":["transform-budget-exceeded"],"policy":null}""",
            body);

        using HttpResponseMessage accepted = await Send(client, Raw(time: DateTimeOffset.UtcNow), cancellation);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        foreach (string forbidden in new[] { "deploy-admin", "Failed password", "bastion-1", "aaaaaaaaaa" })
        {
            Assert.DoesNotContain(forbidden, row.Payload, StringComparison.Ordinal);
        }

        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(request, cancellation);
        using JsonDocument document = JsonDocument.Parse(await status.Content.ReadAsStringAsync(cancellation));
        JsonElement transformRow = Assert.Single(
            document.RootElement.GetProperty("pipeline").GetProperty("rows").EnumerateArray(),
            row => row.GetProperty("stage").GetString() == "transform");
        Assert.Equal("quarantine", transformRow.GetProperty("action").GetString());
        Assert.Equal(1, transformRow.GetProperty("events").GetInt64());
        Assert.Equal(0, transformRow.GetProperty("queued").GetInt64());
    }

    private static async Task<WebApplication> Start(string source, TemporaryDirectory directory, CancellationToken cancellation)
    {
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(source, privateKey, directory.Path);
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(trust, publicKey);
        File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            CollectorId = "transform-pack-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = hmac,
            MaximumQueueBytes = 1_048_576,
            IngestRequestsPerSecond = 1000,
            IngestToken = Token,
            SingleTrustDomain = true
        }, builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    private static async Task<HttpResponseMessage> Send(HttpClient client, string raw, CancellationToken cancellation)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, Endpoint) { Content = new StringContent(raw, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return await client.SendAsync(request, cancellation);
    }
}
