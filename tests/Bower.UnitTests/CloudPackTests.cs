using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Detection;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;
using Bower.Source.Aws;
using Bower.Source.Gcp;

namespace Bower.UnitTests;

public sealed class CloudPackTests
{
    [Theory]
    [InlineData("aws-security", 2)]
    [InlineData("gcp-security", 2)]
    public void Pack_BuildsSignsAndPassesItsSamples(string id, int policies)
    {
        LoadedPack pack = Build(id, out _);

        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

        Assert.Equal(id, pack.Manifest.Id);
        Assert.Equal(policies, pack.Policies.Count);
        Assert.Null(pack.PrivacyProfileYaml);
        Assert.Equal(4, pack.Detections.Count);
        Assert.All(results, result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
    }

    [Fact]
    public async Task MappedCloudEvents_PassCollectorValidationAndPackPolicies()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        LoadedPack aws = Build("aws-security", out _);
        LoadedPack gcp = Build("gcp-security", out _);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, TimeProvider.System);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([.. aws.Policies, .. gcp.Policies]),
            store,
            TimeProvider.System);
        AwsQueueMessageParser parser = new(new AwsQueueOptions { SourceId = "aws:test", AccountId = "123456789012" });
        GcpSecurityEventMapper mapper = new(new GcpSourceOptions { SourceId = "gcp:test" });
        List<SecurityEventEnvelope> events =
        [
            .. parser.Parse(CloudSourceTests.GuardDutyEvent, now).Events,
            .. parser.Parse(CloudSourceTests.RootConsoleLoginFailure, now).Events,
            .. parser.Parse(CloudSourceTests.StopLogging, now).Events,
            .. parser.Parse(CloudSourceTests.SecurityHubEvent, now).Events,
            mapper.Map(Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry), now).Event!,
            mapper.Map(Encoding.UTF8.GetBytes(CloudSourceTests.SccNotification), now).Event!
        ];

        foreach (SecurityEventEnvelope item in events)
        {
            // Fixtures are dated 2026-07; shift them so the collector's clock-skew window accepts them.
            string json = JsonSerializer.Serialize(item with { TimeGenerated = now.AddMinutes(-1) }, BowerJson.Options);
            ProcessingResult result = await processor.ProcessAsync(
                json,
                new CollectorIdentity("collector-test", "1.0.0", "local-http:cloud", "hash"),
                cancellationToken);

            Assert.True(
                result.Action is DecisionAction.Accept or DecisionAction.RedactAndAccept,
                $"{item.EventType}/{item.EventAction}: {result.Action} {string.Join("; ", result.Reasons)}");
            Assert.True(result.Queued);
        }
    }

    [Theory]
    [InlineData("aws", "root", "bower-pack-aws-root-activity-001|bower-pack-aws-console-login-failure-001")]
    [InlineData("aws", "stop", "bower-pack-aws-logging-tampering-001")]
    [InlineData("aws", "guardduty", "")]
    [InlineData("gcp", "audit", "bower-pack-gcp-sa-key-created-001")]
    [InlineData("gcp", "denied", "bower-pack-gcp-permission-denied-001")]
    public void PackDetections_FireOnMappedEvents(string cloud, string fixture, string expected)
    {
        DetectionEngine engine = new([.. Build("aws-security", out _).Detections, .. Build("gcp-security", out _).Detections]);
        AwsQueueMessageParser parser = new(new AwsQueueOptions { SourceId = "aws:test" });
        GcpSecurityEventMapper mapper = new(new GcpSourceOptions { SourceId = "gcp:test" });
        SecurityEventEnvelope envelope = (cloud, fixture) switch
        {
            ("aws", "root") => parser.Parse(CloudSourceTests.RootConsoleLoginFailure, TestEvents.Now).Events[0],
            ("aws", "stop") => parser.Parse(CloudSourceTests.StopLogging, TestEvents.Now).Events[0],
            ("aws", _) => parser.Parse(CloudSourceTests.GuardDutyEvent, TestEvents.Now).Events[0],
            (_, "denied") => mapper.Map(Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry.Replace(
                "\"status\":{}", "\"status\":{\"code\":7}", StringComparison.Ordinal)), TestEvents.Now).Event!,
            _ => mapper.Map(Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry), TestEvents.Now).Event!
        };

        string[] fired = engine.Evaluate(envelope, TestEvents.Now).Alerts.Select(alert => alert.RuleId).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(expected.Split('|', StringSplitOptions.RemoveEmptyEntries).Order(StringComparer.Ordinal), fired);
    }

    [Fact]
    public void CloudIdentityProfile_PseudonymisesPrincipals()
    {
        string yaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "privacy", "cloud-identities.yaml"));
        PrivacyEngine engine = new(PrivacyProfileLoader.Load(yaml, new byte[32], "k1").Policy);
        string json = JsonSerializer.Serialize(
            new GcpSecurityEventMapper(new GcpSourceOptions { SourceId = "gcp:test" })
                .Map(Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry), TestEvents.Now).Event,
            BowerJson.Options);

        string redacted = engine.RedactJson(json).RedactedJson!;

        Assert.DoesNotContain("alice@example.com", redacted, StringComparison.Ordinal);
        Assert.Contains("hmac-sha256:k1:", redacted, StringComparison.Ordinal);
    }

    private static LoadedPack Build(string id, out string publicPem)
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        publicPem = publicKey;
        string archive = PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", id), privatePem, output.Path);
        return PackArchive.Load(archive, [publicPem]);
    }
}
