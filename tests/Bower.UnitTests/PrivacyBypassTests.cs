using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>Adversarial inputs that previously reached persistence unredacted.</summary>
public sealed class PrivacyBypassTests
{
    [Theory]
    [InlineData("""{ "attributes": { "card": 4111111111111111 } }""")]
    [InlineData("""{ "attributes": { "values": [[4111111111111111]] } }""")]
    [InlineData("""{ "attributes": { "4111111111111111": "x" } }""")]
    [InlineData("""{ "attributes": { "nested": { "4111111111111111": { "ok": true } } } }""")]
    public void RedactJson_RemovesCardNumbersInNumbersAndKeys(string json)
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("4111111111111111", result.RedactedJson, StringComparison.Ordinal);
        Assert.Contains(result.Findings, finding => finding.DetectorId == DetectorIds.CreditCard);
    }

    [Fact]
    public void RedactJson_MasksSensitiveKeyAndKeepsItsValue()
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            """{ "alice@example.test": "member" }""");

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("alice@example.test", result.RedactedJson, StringComparison.Ordinal);
        Assert.Contains("\"a***@example.test\":\"member\"", result.RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactJson_RenamesRemovedKeysWithoutCollisions()
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            """{ "4111111111111111": 1, "5555555555554444": 2 }""");

        Assert.True(result.Succeeded);
        using JsonDocument document = JsonDocument.Parse(result.RedactedJson!);
        Assert.Equal(1, document.RootElement.GetProperty("redacted-key-1").GetInt32());
        Assert.Equal(2, document.RootElement.GetProperty("redacted-key-2").GetInt32());
    }

    [Fact]
    public void RedactJson_LeavesOrdinaryNumbersUntouched()
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            """{ "statusCode": 401, "port": 443, "score": 87.5 }""");

        Assert.True(result.Succeeded);
        Assert.Equal("""{"statusCode":401,"port":443,"score":87.5}""", result.RedactedJson);
    }

    [Theory]
    [InlineData("dbPassword")]
    [InlineData("sessionToken")]
    [InlineData("idToken")]
    [InlineData("setCookie")]
    [InlineData("pwd")]
    [InlineData("xApiKey")]
    [InlineData("client_secret")]
    [InlineData("userPass")]
    [InlineData("mfa_otp")]
    [InlineData("AWS_SECRET_ACCESS_KEY")]
    public void RedactJson_RemovesSecretFieldNameVariants(string fieldName)
    {
        string json = JsonSerializer.Serialize(
            new Dictionary<string, string> { [fieldName] = "plain-secret-value" });

        PrivacyScanResult result = new PrivacyEngine().RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("plain-secret-value", result.RedactedJson, StringComparison.Ordinal);
        Assert.Contains(result.Findings, finding => finding.DetectorId == DetectorIds.FieldNameSecret);
    }

    [Theory]
    [InlineData("tokenType")]
    [InlineData("passwordLastChanged")]
    [InlineData("bypass")]
    [InlineData("eventType")]
    [InlineData("sessionId")]
    public void RedactJson_KeepsSecretMetadataFieldNames(string fieldName)
    {
        string json = JsonSerializer.Serialize(
            new Dictionary<string, string> { [fieldName] = "kept" });

        PrivacyScanResult result = new PrivacyEngine().RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.Contains("kept", result.RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void PrivacyEngine_RefusesHmacWithoutKey()
    {
        PrivacyPolicy policy = new()
        {
            DetectorActions = new Dictionary<string, PrivacyAction>(StringComparer.Ordinal)
            {
                [DetectorIds.Tfn] = PrivacyAction.Hmac
            }
        };

        Assert.Throws<InvalidOperationException>(() => new PrivacyEngine(policy));
    }

    [Fact]
    public void PrivacyEngine_UsesKeyedHashWhenHmacKeyConfigured()
    {
        PrivacyPolicy policy = new()
        {
            HmacKey = new byte[32],
            DetectorActions = new Dictionary<string, PrivacyAction>(StringComparer.Ordinal)
            {
                [DetectorIds.Tfn] = PrivacyAction.Hmac
            }
        };

        PrivacyScanResult result = new PrivacyEngine(policy).RedactJson("""{ "tfn": "100000001" }""");

        Assert.True(result.Succeeded);
        Assert.Contains("hmac-sha256:", result.RedactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("sha256:", result.RedactedJson!.Replace("hmac-sha256:", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public void RedactJson_QuarantinesDuplicateKeysInsteadOfThrowing()
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            """{ "a": "1", "a": "2" }""");

        Assert.False(result.Succeeded);
        Assert.True(result.FailureCode is "redaction-failed" or "invalid-json");
    }

    [Fact]
    public async Task Process_QuarantinesWithoutPersistingWhenRedactorThrows()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new ThrowingRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock);

        ProcessingResult result = await processor.ProcessAsync(
            JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Contains("redaction-failed", result.Reasons);
        Assert.Equal(0, snapshot.Queued);
    }

    [Fact]
    public async Task Process_RetriedEventProducesOnePrivacyAlert()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator(
                [TestEvents.AuthenticationPolicy(), TestEvents.PrivacyDetectionPolicy()]),
            store,
            clock);
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["password"] = JsonSerializer.SerializeToElement("never-persist")
            }
        };
        string json = JsonSerializer.Serialize(candidate, BowerJson.Options);
        CollectorIdentity identity = new("collector-1", "0.1.0", "test", "sha256:configuration");

        ProcessingResult first = await processor.ProcessAsync(json, identity, cancellationToken);
        clock.Advance(TimeSpan.FromSeconds(30));
        ProcessingResult retry = await processor.ProcessAsync(json, identity, cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);

        Assert.NotNull(first.PrivacyAlertEventId);
        Assert.Equal(first.PrivacyAlertEventId, retry.PrivacyAlertEventId);
        Assert.Equal(2, snapshot.Queued);
    }

    private sealed class ThrowingRedactor : IEventRedactor
    {
        public RedactionResult Redact(string json) =>
            throw new System.Text.RegularExpressions.RegexMatchTimeoutException();
    }
}
