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
using Bower.Persistence;
using Bower.Pipeline;
using Bower.PolicyEngine;
using Bower.Redaction;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class PackActivationTests
{
    private const string Token = "pack-activation-test-token-0123456789abcdef";
    private const string Endpoint = "/v1/packs/linux-ssh-gateway/parsers/0/events";
    private static string Source => Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway");

    [Fact]
    public async Task SignedPack_RawRecordBecomesRedactedDurableDetection_AndReplayDeduplicates()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using HttpClient client = app.GetTestClient();
        string raw = Raw();
        using HttpResponseMessage first = await Send(client, raw, cancellation);
        using HttpResponseMessage replay = await Send(client, raw, cancellation);
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);

        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        Assert.DoesNotContain("raw-secret-never-forwarded", row.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy-admin", row.Payload, StringComparison.Ordinal);
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
        Assert.Equal("authentication_failure", stored.EventType);
        Assert.Equal("pack-http:default:linux-ssh-gateway:0", stored.Collector!.SourceAdapter);
        JsonElement detection = Assert.Single(stored.Attributes![PackDetectionRedactor.EvidenceAttribute].EnumerateArray());
        Assert.Equal("bower-pack-ssh-auth-failure-001", detection.GetProperty("ruleId").GetString());
        Assert.Equal("1.0.0", detection.GetProperty("ruleVersion").GetString());
        Assert.Equal(64, detection.GetProperty("ruleHash").GetString()!.Length);
        Assert.Contains("T1110", detection.GetProperty("mitreTechniques").EnumerateArray().Select(item => item.GetString()));

        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(request, cancellation);
        string statusText = await status.Content.ReadAsStringAsync(cancellation);
        Assert.Contains("active-local-json", statusText, StringComparison.Ordinal);
        Assert.Contains("active-local", statusText, StringComparison.Ordinal);
        Assert.Contains("packaged-only", statusText, StringComparison.Ordinal);
        foreach (string path in Directory.EnumerateFiles(directory.Path, "queue.db*"))
        {
            string bytes = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path, cancellation));
            Assert.DoesNotContain("raw-secret-never-forwarded", bytes, StringComparison.Ordinal);
            Assert.DoesNotContain("deploy-admin", bytes, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("unmatched", 422)]
    [InlineData("duplicate", 400)]
    [InlineData("missing", 400)]
    [InlineData("oversized", 413)]
    [InlineData("wrong-type", 400)]
    [InlineData("no-token", 401)]
    [InlineData("no-scope", 403)]
    [InlineData("unknown-parser", 404)]
    [InlineData("malformed", 400)]
    [InlineData("unauthenticated-malformed", 401)]
    [InlineData("whitespace-oversized", 413)]
    [InlineData("invalid-ip", 400)]
    [InlineData("abbreviated-ip", 400)]
    [InlineData("scoped-ip", 400)]
    [InlineData("deep", 400)]
    public async Task RawIntake_FailsClosedWithoutQueueing(string variant, int expectedStatus)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation, singleTrustDomain: variant != "no-scope");
        using HttpClient client = app.GetTestClient();
        string raw = variant switch
        {
            "unmatched" => Raw().Replace("\"failure\"", "\"success\"", StringComparison.Ordinal),
            "duplicate" => Raw().Replace("\"result\":", "\"result\":\"success\",\"result\":", StringComparison.Ordinal),
            "missing" => "{}",
            "malformed" or "unauthenticated-malformed" => "{",
            "whitespace-oversized" => new string(' ', 33_000) + Raw(),
            "abbreviated-ip" => Raw().Replace("203.0.113.5", "127.1", StringComparison.Ordinal),
            "scoped-ip" => Raw().Replace("203.0.113.5", "fe80::1%1", StringComparison.Ordinal),
            "invalid-ip" => Raw().Replace("203.0.113.5", "not-an-address", StringComparison.Ordinal),
            "deep" => Raw().Replace("\"password\":", "\"deep\":" + new string('[', 16) + "0" + new string(']', 16) + ",\"password\":", StringComparison.Ordinal),
            "oversized" => "{\"ignored\":\"" + new string('x', 33_000) + "\"}",
            "wrong-type" => Raw().Replace("\"203.0.113.5\"", "123", StringComparison.Ordinal),
            _ => Raw()
        };
        using HttpResponseMessage response = await Send(client, raw, cancellation,
            variant is not ("no-token" or "unauthenticated-malformed"), variant == "unknown-parser" ? Endpoint.Replace("/0/", "/99/", StringComparison.Ordinal) : Endpoint);
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        Assert.DoesNotContain("raw-secret-never-forwarded", await response.Content.ReadAsStringAsync(cancellation), StringComparison.Ordinal);
        Assert.Equal(0, (await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    [Theory]
    [InlineData("unknown-target")]
    [InlineData("empty-filter")]
    [InlineData("unsupported-format")]
    [InlineData("unknown-runtime-property")]
    public void Signing_RejectsInvalidRuntimeMappings(string attack)
    {
        using TemporaryDirectory directory = new();
        CopyPack(directory.Path);
        string path = Path.Combine(directory.Path, "parsers", "sshd-json.json");
        JsonObject parser = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        JsonObject runtime = parser["runtime"]!.AsObject();
        switch (attack)
        {
            case "unknown-target": runtime["fields"]!["attributes.raw"] = "user"; break;
            case "empty-filter": runtime["match"] = new JsonObject(); break;
            case "unsupported-format": parser["format"] = "KeyValue"; parser["keyValueSeparator"] = "="; break;
            case "unknown-runtime-property": runtime["eventTypo"] = "allow-anything"; break;
        }
        File.WriteAllText(path, parser.ToJsonString());
        (string privateKey, _, _) = DetachedSigner.GenerateKeyPair();
        Assert.ThrowsAny<Exception>(() => PackArchive.Build(directory.Path, privateKey, Path.Combine(directory.Path, "out")));
        Assert.False(Directory.Exists(Path.Combine(directory.Path, "out")));
    }

    [Fact]
    public void Signing_ExecutesExpectedDetectionsOnRawSamples()
    {
        using TemporaryDirectory directory = new();
        CopyPack(directory.Path);
        string samples = Path.Combine(directory.Path, "samples", "ssh.jsonl");
        File.WriteAllText(samples, File.ReadAllText(samples).Replace(
            "\"expectedDetections\":[\"bower-pack-ssh-auth-failure-001\"]", "\"expectedDetections\":[\"wrong-rule\"]", StringComparison.Ordinal));
        (string privateKey, _, _) = DetachedSigner.GenerateKeyPair();
        InvalidDataException failure = Assert.Throws<InvalidDataException>(() => PackArchive.Build(directory.Path, privateKey, Path.Combine(directory.Path, "out")));
        Assert.Contains("Expected detection rule ids", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("selection and missing")]
    [InlineData("1 of selection*")]
    [InlineData("selection | count() > 1")]
    public void Signing_RejectsUnsupportedDetectionBeforeWritingArchive(string condition)
    {
        using TemporaryDirectory directory = new();
        CopyPack(directory.Path);
        string path = Path.Combine(directory.Path, "detections", "ssh-password-spray.yml");
        File.WriteAllText(path, File.ReadAllText(path).Replace("condition: selection", "condition: " + condition, StringComparison.Ordinal));
        (string privateKey, _, _) = DetachedSigner.GenerateKeyPair();
        Assert.Throws<InvalidDataException>(() => PackArchive.Build(directory.Path, privateKey, Path.Combine(directory.Path, "out")));
        Assert.False(Directory.Exists(Path.Combine(directory.Path, "out")));
    }

    [Fact]
    public async Task PreviewOnlyParser_IsReportedInactiveAndCannotIngest()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation, active: false);
        using HttpClient client = app.GetTestClient();
        using HttpResponseMessage response = await Send(client, Raw(), cancellation);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(request, cancellation);
        Assert.Contains("inactive-preview-only", await status.Content.ReadAsStringAsync(cancellation), StringComparison.Ordinal);
        Assert.Equal(0, (await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    [Fact]
    public async Task RawIntake_RedactionFailureNeverPersistsOriginal()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation, redactor: new FailedRedactor());
        using HttpClient client = app.GetTestClient();
        using HttpResponseMessage response = await Send(client, Raw(), cancellation);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("deploy-admin", await response.Content.ReadAsStringAsync(cancellation), StringComparison.Ordinal);
        Assert.Equal(0, (await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    private sealed class FailedRedactor : IEventRedactor
    {
        public RedactionResult Redact(string json) => throw new InvalidOperationException("synthetic-redactor-failure");
    }

    [Theory]
    [InlineData("labels", "collision")]
    [InlineData("labels", "count")]
    [InlineData("labels", "key")]
    [InlineData("attributes", "collision")]
    [InlineData("attributes", "count")]
    [InlineData("attributes", "key")]
    public async Task DetectionMetadataFailure_QuarantinesMatchingEventWithoutPersistingSource(string field, string attack)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using HttpClient client = app.GetTestClient();
        const string marker = "detection-source-marker";
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow) with
        {
            Application = new ApplicationContext { Name = "ssh-gateway", Environment = "production" },
            EventOutcomeReason = marker
        };
        Dictionary<string, string> metadata = attack switch
        {
            "collision" => new() { ["x"] = "harmless", ["X"] = "harmless" },
            "count" => Enumerable.Range(0, 257).ToDictionary(index => $"x{index}", _ => "harmless"),
            _ => new() { [new string('x', field == "attributes" ? 118 : 129)] = "harmless" }
        };
        envelope = field == "labels"
            ? envelope with { Labels = metadata }
            : envelope with { Attributes = metadata.ToDictionary(pair => pair.Key, pair => JsonSerializer.SerializeToElement(pair.Value)) };

        using HttpResponseMessage rejected = await Send(client, JsonSerializer.Serialize(envelope, BowerJson.Envelope), cancellation, endpoint: "/v1/events");
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        string response = await rejected.Content.ReadAsStringAsync(cancellation);
        Assert.Contains("pack-detection-failed", response, StringComparison.Ordinal);
        Assert.Contains("quarantine", response, StringComparison.Ordinal);
        Assert.DoesNotContain(marker, response, StringComparison.Ordinal);
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellation)).Queued);
        foreach (string path in Directory.EnumerateFiles(directory.Path, "queue.db*"))
        {
            Assert.DoesNotContain(marker, Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path, cancellation)), StringComparison.Ordinal);
        }

        // The same source event succeeds after metadata is repaired: failure must not deduplicate it.
        envelope = envelope with { Labels = null, Attributes = null };
        using HttpResponseMessage repaired = await Send(client, JsonSerializer.Serialize(envelope, BowerJson.Envelope), cancellation, endpoint: "/v1/events");
        Assert.Equal(HttpStatusCode.Accepted, repaired.StatusCode);
        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
        Assert.Equal("bower-pack-ssh-auth-failure-001", Assert.Single(stored.Attributes![PackDetectionRedactor.EvidenceAttribute].EnumerateArray()).GetProperty("ruleId").GetString());
    }

    [Theory]
    [InlineData("bowerDetections")]
    [InlineData("BOWERDETECTIONS")]
    public void DetectionEvidence_CannotBeForgedByProducer(string key)
    {
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                [key] = JsonDocument.Parse("[\"forged-rule\"]").RootElement.Clone()
            }
        };
        PackDetectionRedactor redactor = new(new JsonEventRedactor(), new DeterministicPolicyEvaluator([]), []);
        RedactionResult result = redactor.Redact(JsonSerializer.Serialize(envelope, BowerJson.Envelope));
        Assert.True(result.Succeeded);
        Assert.DoesNotContain("forged-rule", result.RedactedJson!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DetectionEvidence_ReservedAttributesAreRemovedBeforeBoundsAndReplacedOnReplay()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using HttpClient client = app.GetTestClient();
        Dictionary<string, JsonElement> attributes = Enumerable.Range(0, 256)
            .ToDictionary(index => $"x{index}", _ => JsonSerializer.SerializeToElement("harmless"));
        attributes["bowerDetections"] = JsonSerializer.SerializeToElement("forged-rule");
        attributes["BOWERDETECTIONS"] = JsonSerializer.SerializeToElement("forged-rule");
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow) with
        {
            Application = new ApplicationContext { Name = "ssh-gateway", Environment = "production" },
            Attributes = attributes
        };
        using HttpResponseMessage accepted = await Send(client, JsonSerializer.Serialize(envelope, BowerJson.Envelope), cancellation, endpoint: "/v1/events");
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        QueuedEvent row = Assert.Single(await app.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        Assert.DoesNotContain("forged-rule", row.Payload, StringComparison.Ordinal);
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
        Assert.Equal(257, stored.Attributes!.Count);
        Assert.Single(stored.Attributes[PackDetectionRedactor.EvidenceAttribute].EnumerateArray());
        envelope = envelope with { Attributes = stored.Attributes };
        using HttpResponseMessage replay = await Send(client, JsonSerializer.Serialize(envelope, BowerJson.Envelope), cancellation, endpoint: "/v1/events");
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
    }

    [Fact]
    public async Task RawIntake_BackpressurePreservesQueueAndAllowsRetryAfterSpaceIsFreed()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using HttpClient client = app.GetTestClient();
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        await store.EnqueueAsync(new QueuedEvent("filler", "sha256:filler", new string('x', 1_048_000), DateTimeOffset.UtcNow), cancellation);
        string raw = Raw();
        using HttpResponseMessage blocked = await Send(client, raw, cancellation);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, blocked.StatusCode);
        QueuedEvent filler = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        Assert.Equal("filler", filler.EventId);
        await store.MarkDeliveredAsync(filler.EventId, "test-ack", filler.LeaseToken, cancellation);
        using HttpResponseMessage retried = await Send(client, raw, cancellation);
        Assert.Equal(HttpStatusCode.Accepted, retried.StatusCode);
        Assert.Equal("activation-1", Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation)).EventId);
    }

    [Fact]
    public async Task RawIntake_RateLimitsBeforeParsing()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation, rate: 1);
        using HttpClient client = app.GetTestClient();
        List<HttpStatusCode> statuses = [];
        for (int index = 0; index < 4; index++)
        {
            using HttpResponseMessage response = await Send(client, "{", cancellation);
            statuses.Add(response.StatusCode);
        }
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
        Assert.Equal(0, (await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    [Fact]
    public async Task RawIntake_CancelledBodyReadPersistsNothing()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using CancellationTokenSource aborted = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        using PendingBody body = new();
        Task request = app.GetTestServer().SendAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.Path = Endpoint;
            context.Request.ContentType = "application/json";
            context.Request.Headers.Authorization = "Bearer " + Token;
            context.Request.Body = body;
        }, aborted.Token);
        await body.Started.Task.WaitAsync(cancellation);
        await aborted.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        Assert.Equal(0, (await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    [Fact]
    public async Task StoredDetectionEvidence_SurvivesRestartAndReplay()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        using HttpClient client = app.GetTestClient();
        string raw = Raw();
        using HttpResponseMessage accepted = await Send(client, raw, cancellation);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        CollectorSettings settings = app.Services.GetRequiredService<CollectorSettings>();
        await app.StopAsync(cancellation);
        await using WebApplication restarted = CollectorApplication.Build(settings, builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(restarted, cancellation);
        await restarted.StartAsync(cancellation);
        using HttpClient secondClient = restarted.GetTestClient();
        using HttpResponseMessage replay = await Send(secondClient, raw, cancellation);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        QueuedEvent row = Assert.Single(await restarted.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        Assert.Contains("bower-pack-ssh-auth-failure-001", row.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy-admin", row.Payload, StringComparison.Ordinal);
    }

    private sealed class PendingBody : MemoryStream
    {
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    private static async Task<WebApplication> Start(TemporaryDirectory directory, CancellationToken cancellation, bool singleTrustDomain = true, int rate = 1000, bool active = true, IEventRedactor? redactor = null)
    {
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string source = Source;
        if (!active)
        {
            source = Path.Combine(directory.Path, "preview-only");
            CopyPack(source);
            string parserPath = Path.Combine(source, "parsers", "sshd-json.json");
            JsonObject parser = JsonNode.Parse(File.ReadAllText(parserPath))!.AsObject();
            parser.Remove("runtime");
            File.WriteAllText(parserPath, parser.ToJsonString());
            string samples = Path.Combine(source, "samples", "ssh.jsonl");
            File.WriteAllLines(samples, File.ReadAllLines(samples).Where(line => !line.Contains("\"raw\":", StringComparison.Ordinal)));
        }
        string archive = PackArchive.Build(source, privateKey, directory.Path);
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(trust, publicKey);
        File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            CollectorId = "pack-activation-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = hmac,
            MaximumQueueBytes = 1_048_576,
            IngestRequestsPerSecond = rate,
            IngestToken = Token,
            SingleTrustDomain = singleTrustDomain
        }, builder =>
        {
            builder.WebHost.UseTestServer();
            if (redactor is not null) { builder.Services.AddSingleton(redactor); }
        });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    private static string Raw() => $$"""{"id":"activation-1","timestamp":"{{DateTimeOffset.UtcNow:O}}","user":"deploy-admin","source_ip":"203.0.113.5","result":"failure","password":"raw-secret-never-forwarded"}""";

    private static async Task<HttpResponseMessage> Send(HttpClient client, string raw, CancellationToken cancellation,
        bool token = true, string endpoint = Endpoint)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint) { Content = new StringContent(raw, Encoding.UTF8, "application/json") };
        if (token) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return await client.SendAsync(request, cancellation);
    }

    private static void CopyPack(string destination)
    {
        foreach (string path in Directory.EnumerateFiles(Source, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(destination, Path.GetRelativePath(Source, path));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(path, target);
        }
    }
}
