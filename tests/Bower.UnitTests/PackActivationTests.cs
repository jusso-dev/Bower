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
        Assert.Equal("pack-http:shared:linux-ssh-gateway:0", stored.Collector!.SourceAdapter);
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
            "oversized" => "{\"ignored\":\"" + new string('x', 33_000) + "\"}",
            "wrong-type" => Raw().Replace("\"203.0.113.5\"", "123", StringComparison.Ordinal),
            _ => Raw()
        };
        using HttpResponseMessage response = await Send(client, raw, cancellation,
            variant != "no-token", variant == "unknown-parser" ? Endpoint.Replace("/0/", "/99/", StringComparison.Ordinal) : Endpoint);
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

    [Fact]
    public void DetectionEvidence_CannotBeForgedByProducer()
    {
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                [PackDetectionRedactor.EvidenceAttribute] = JsonSerializer.SerializeToElement(new[] { "forged-rule" })
            }
        };
        PackDetectionRedactor redactor = new(new JsonEventRedactor(), new DeterministicPolicyEvaluator([]), []);
        RedactionResult result = redactor.Redact(JsonSerializer.Serialize(envelope, BowerJson.Envelope));
        Assert.True(result.Succeeded);
        Assert.DoesNotContain("forged-rule", result.RedactedJson!, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> Start(TemporaryDirectory directory, CancellationToken cancellation, bool singleTrustDomain = true)
    {
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(Source, privateKey, directory.Path);
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(trust, publicKey);
        File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive], PackTrustedKeyFiles = [trust], PrivacyHmacKeyFile = hmac,
            IngestToken = Token, SingleTrustDomain = singleTrustDomain
        }, builder => builder.WebHost.UseTestServer());
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
