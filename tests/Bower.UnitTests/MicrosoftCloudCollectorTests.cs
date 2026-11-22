using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Detection;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.Redaction.Privacy;
using Bower.Source.MicrosoftCloud;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// The Microsoft cloud source inside the collector: Intune audit events and compliance
/// records from a fake Graph become durable events only through the signed
/// <c>microsoft-intune</c> parsers (transforms, match filter), redaction and policy.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class MicrosoftCloudCollectorTests
{
    private const string Token = "microsoft-cloud-collector-test-token-0123456789";
    private static string PackSource => Path.Combine(AppContext.BaseDirectory, "packs", "microsoft-intune");

    [Fact]
    public void Pack_BuildsSignsAndPassesItsSamples()
    {
        LoadedPack pack = Build(out _);

        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

        Assert.Equal("microsoft-intune", pack.Manifest.Id);
        Assert.Equal(2, pack.Policies.Count);
        Assert.Equal(2, pack.Parsers.Count);
        Assert.Equal(4, pack.Detections.Count);
        Assert.Null(pack.PrivacyProfileYaml);
        Assert.All(results, result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
    }

    [Fact]
    public async Task IntuneAuditAndCompliance_AreRedactedQueuedAndDeduplicatedAcrossRestart()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        // Real time plus an offset: collector timers keep running, and the restart can be moved
        // past the settle delay so the audit input really re-reads its overlap.
        ShiftedClock clock = new();
        DateTimeOffset now = clock.GetUtcNow();
        MicrosoftCloudSourceTests.FakeGraph graph = new();
        graph.AuditPages(now);
        graph.Respond(uri => uri.AbsolutePath.EndsWith("/managedDevices", StringComparison.Ordinal),
            MicrosoftCloudSourceTests.Fixture("intune-managed-devices.json", now));
        List<QueuedEvent> rows;
        await using (WebApplication app = await Start(directory, graph, clock, cancellation))
        {
            MicrosoftCloudSource source = app.Services.GetRequiredService<MicrosoftCloudSource>();
            await WaitFor(source, items => items.All(item => item.Queued + item.Duplicates >= 2), cancellation);
            MicrosoftCloudInputStatus[] statuses = [.. source.Snapshot().OrderBy(item => item.Id, StringComparer.Ordinal)];
            Assert.Equal(2, statuses[0].Queued);
            Assert.Equal(1, statuses[0].OutOfScope);
            Assert.Equal(2, statuses[1].Queued);
            Assert.Equal(1, statuses[1].OutOfScope);

            using HttpClient client = app.GetTestClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            using JsonDocument status = JsonDocument.Parse(await client.GetStringAsync("/v1/status", cancellation));
            JsonElement reported = status.RootElement.GetProperty("microsoftCloud");
            Assert.Equal(2, reported.GetArrayLength());
            Assert.DoesNotContain("contoso.example", reported.GetRawText(), StringComparison.Ordinal);
            Assert.DoesNotContain("graph.microsoft.com", reported.GetRawText(), StringComparison.Ordinal);

            rows = [.. await app.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation)];
        }

        Assert.Equal(4, rows.Count);
        SecurityEventEnvelope[] events = [.. rows.Select(row => JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!)];
        foreach (QueuedEvent row in rows)
        {
            Assert.DoesNotContain("megan.bowen@contoso.example", row.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("adele.vance@contoso.example", row.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("MEGAN-LAPTOP", row.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("KIOSK-03", row.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("secret-", row.Payload, StringComparison.Ordinal);
        }

        SecurityEventEnvelope wipe = Assert.Single(events, item => item.EventAction == "Wipe ManagedDevice");
        Assert.Equal("intune_audit", wipe.EventType);
        Assert.Equal("microsoft-intune", wipe.Application.Name);
        Assert.Equal("203.0.113.40", wipe.Source!.IpAddress);
        Assert.Equal("mscloud:intune-audit:microsoft-intune:0", wipe.Collector!.SourceAdapter);
        Assert.StartsWith("mscloud-", wipe.EventId, StringComparison.Ordinal);
        Assert.StartsWith("hmac-sha256:", wipe.Actor!.Username, StringComparison.Ordinal);
        Assert.Contains(wipe.Attributes!["bowerDetections"].EnumerateArray(),
            item => item.GetProperty("ruleId").GetString() == "bower-pack-intune-device-wipe-001");
        SecurityEventEnvelope kiosk = Assert.Single(events, item => item.EventAction == "device.compliance.inGracePeriod");
        Assert.Equal("True", kiosk.Labels!["jailBroken"]);
        Assert.Equal("22222222-0000-4000-8000-000000000803", kiosk.Target!.Id);

        // Restart both inputs 15 minutes later (same UTC day unless the test runs just before
        // midnight, which the snapshot assertion allows for). The audit window re-reads its
        // 10 minute overlap, which holds the role change: it must be a queue duplicate.
        int requestsBefore = graph.Requests.Count;
        clock.Offset = TimeSpan.FromMinutes(15);
        bool sameDay = clock.GetUtcNow().UtcDateTime.Date == now.UtcDateTime.Date;
        await using (WebApplication again = await Start(directory, graph, clock, cancellation))
        {
            MicrosoftCloudSource source = again.Services.GetRequiredService<MicrosoftCloudSource>();
            await WaitFor(source, items => items.Single(item => item.Id == "intune-audit").Duplicates >= 1
                && items.Single(item => item.Id == "intune-compliance").State == (sameDay ? "idle" : "running"), cancellation);
            MicrosoftCloudInputStatus audit = source.Snapshot().Single(item => item.Id == "intune-audit");
            Assert.Equal(0, audit.Queued);
            Assert.True(graph.Requests.Count > requestsBefore);
            if (sameDay)
            {
                Assert.Equal(0, source.Snapshot().Single(item => item.Id == "intune-compliance").Pages);
            }

            // Exactly the four rows from the first run, whatever state the leases left them in.
            QueueSnapshot queue = await again.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation);
            Assert.Equal(4, queue.Queued + queue.Uploading + queue.Retrying + queue.Delivered + queue.DeadLettered);
        }
    }

    /// <summary>System time plus an adjustable offset.</summary>
    private sealed class ShiftedClock : TimeProvider
    {
        public TimeSpan Offset { get; set; }

        public override DateTimeOffset GetUtcNow() => System.GetUtcNow() + Offset;
    }

    [Fact]
    public async Task RouteToAMissingParser_StopsStartUp()
    {
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, parser: 7);

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(
            () => CollectorApplication.Build(settings, builder => builder.WebHost.UseTestServer()));

        Assert.Contains("is not an active parser of a loaded pack", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Setting_IsReadAndChangesTheConfigurationHash()
    {
        CollectorSettings plain = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_LISTEN_URL" => "http://127.0.0.1:4319",
            _ => null
        });
        CollectorSettings configured = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_LISTEN_URL" => "http://127.0.0.1:4319",
            "BOWER_MICROSOFT_CONFIG" => "/etc/bower/microsoft.json",
            _ => null
        });

        Assert.Null(plain.MicrosoftCloudConfigPath);
        Assert.Equal("/etc/bower/microsoft.json", configured.MicrosoftCloudConfigPath);
        Assert.NotEqual(plain.ConfigurationHash(), configured.ConfigurationHash());
    }

    [Fact]
    public void MicrosoftCloudProfile_PseudonymisesPeopleAndResourceNames()
    {
        string yaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "privacy", "microsoft-cloud.yaml"));
        PrivacyEngine engine = new(PrivacyProfileLoader.Load(yaml, new byte[32], "k1").Policy);
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(TestEvents.Now) with
        {
            Actor = new ActorContext { Username = "megan.bowen@contoso.example", UserId = "0b7c1d3e-0000-4000-8000-000000000101" },
            Target = new TargetContext { Type = "RoleAssignment", Id = "5a5a5a5a-0000-4000-8000-000000000301", Name = "Helpdesk operators" }
        };

        string redacted = engine.RedactJson(JsonSerializer.Serialize(envelope, BowerJson.Options)).RedactedJson!;

        string other = engine.RedactJson(JsonSerializer.Serialize(envelope with
        {
            Actor = new ActorContext { Username = "mark.smith@contoso.example" }
        }, BowerJson.Options)).RedactedJson!;
        using JsonDocument first = JsonDocument.Parse(redacted);
        using JsonDocument second = JsonDocument.Parse(other);
        string megan = first.RootElement.GetProperty("actor").GetProperty("username").GetString()!;
        string mark = second.RootElement.GetProperty("actor").GetProperty("username").GetString()!;
        // Same initial and domain: the pseudonyms must still differ (no mask-then-hash collapse).
        Assert.StartsWith("hmac-sha256:", megan, StringComparison.Ordinal);
        Assert.StartsWith("hmac-sha256:", mark, StringComparison.Ordinal);
        Assert.NotEqual(megan, mark);
        Assert.DoesNotContain("***", megan, StringComparison.Ordinal);

        Assert.DoesNotContain("megan.bowen", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("0b7c1d3e-0000-4000-8000-000000000101", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("Helpdesk operators", redacted, StringComparison.Ordinal);
        Assert.Contains("5a5a5a5a-0000-4000-8000-000000000301", redacted, StringComparison.Ordinal);
    }

    private static async Task WaitFor(MicrosoftCloudSource source, Func<IReadOnlyList<MicrosoftCloudInputStatus>, bool> condition, CancellationToken cancellation)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(20);
        while (true)
        {
            IReadOnlyList<MicrosoftCloudInputStatus> status = source.Snapshot();
            if (condition(status))
            {
                return;
            }

            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail("Timed out waiting for the Microsoft cloud inputs: " + JsonSerializer.Serialize(status));
            }

            await Task.Delay(25, cancellation);
        }
    }

    private static async Task<WebApplication> Start(TemporaryDirectory directory, MicrosoftCloudSourceTests.FakeGraph graph, TimeProvider clock, CancellationToken cancellation)
    {
        WebApplication app = CollectorApplication.Build(Settings(directory), builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton(clock);
            builder.Services.AddSingleton<IMicrosoftCloudTokenProvider>(new MicrosoftCloudSourceTests.FakeTokens());
            builder.Services.AddSingleton(new MicrosoftCloudHttpClient(new HttpClient(graph)));
        });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    private static CollectorSettings Settings(TemporaryDirectory directory, int parser = 0)
    {
        string archive = Path.Combine(directory.Path, "microsoft-intune.bowerpack");
        string trust = Path.Combine(directory.Path, "trusted.pem");
        if (!File.Exists(archive))
        {
            (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
            File.Move(PackArchive.Build(PackSource, privateKey, directory.Path), archive);
            File.WriteAllText(trust, publicKey);
            File.WriteAllText(Path.Combine(directory.Path, "hmac.key"), Convert.ToBase64String(new byte[32]));
        }

        JsonArray inputs =
        [
            new JsonObject
            {
                ["id"] = "intune-audit",
                ["sourceKind"] = "intune-audit",
                ["tenantId"] = "a1b2c3d4-0000-4000-8000-00000000aaaa",
                ["route"] = new JsonObject { ["pack"] = "microsoft-intune", ["parser"] = parser }
            }
        ];
        inputs.Add(new JsonObject
        {
            ["id"] = "intune-compliance",
            ["sourceKind"] = "intune-device-compliance",
            ["tenantId"] = "a1b2c3d4-0000-4000-8000-00000000aaaa",
            ["route"] = new JsonObject { ["pack"] = "microsoft-intune", ["parser"] = 1 }
        });

        string configuration = Path.Combine(directory.Path, "microsoft.json");
        File.WriteAllText(configuration, new JsonObject
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "MicrosoftCloudSource",
            ["inputs"] = inputs
        }.ToJsonString());
        return new CollectorSettings
        {
            CollectorId = "microsoft-cloud-collector-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyProfilePath = Path.Combine(AppContext.BaseDirectory, "deploy", "privacy", "microsoft-cloud.yaml"),
            PrivacyHmacKeyFile = Path.Combine(directory.Path, "hmac.key"),
            MaximumQueueBytes = 4_194_304,
            IngestToken = Token,
            SingleTrustDomain = true,
            MicrosoftCloudConfigPath = configuration
        };
    }

    private static LoadedPack Build(out string publicPem)
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        publicPem = publicKey;
        return PackArchive.Load(PackArchive.Build(PackSource, privatePem, output.Path), [publicPem]);
    }
}
