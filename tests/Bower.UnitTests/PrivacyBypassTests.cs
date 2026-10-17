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

    [Fact]
    public void RedactJson_MaskingNeverSplitsSurrogatePairsOrDuplicatesKeys()
    {
        // Masks used to keep value[..2], half of a surrogate pair, so keys differing only
        // in that pair were written as the same U+FFFD name (duplicate JSON keys).
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            "{\"PayID: a\U0001F600bc\":1,\"PayID: a\U0001F300bc\":2,\"PayID: abc\U0001F600x\":3,\"PayID: abc\U0001F300x\":4}");

        Assert.True(result.Succeeded);
        Assert.StartsWith(
            """{"PayID: a**bc":1,"redacted-key-1":2,"PayID: ab***x":3,"redacted-key-2":4,""",
            result.RedactedJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain("FFFD", result.RedactedJson, StringComparison.Ordinal);
        AssertUniqueKeys(result.RedactedJson!);
    }

    [Theory]
    [InlineData("PayID: \U0001F600\U0001F600x", "PayID: \U0001F600**x")]
    [InlineData("PayID: ab\U0001F600cd", "PayID: ab**cd")]
    [InlineData("PayID: a\U0001F600bc", "PayID: a**bc")]
    [InlineData("PayID: abcd\U0001F600", "PayID: ab**\U0001F600")]
    [InlineData("PayID: ab\U0001F600", "PayID: ****")]
    public void RedactText_MaskKeepsSurrogatePairsWhole(string text, string expected)
    {
        PrivacyTextResult result = new PrivacyEngine().RedactText(text);

        Assert.True(result.Succeeded);
        Assert.Equal(expected, result.RedactedText);
    }

    [Fact]
    public void RedactJson_KeysWithUnpairedSurrogatesFromCustomDetectorsStayUnique()
    {
        // A custom detector removing only the low surrogate leaves keys that differ only
        // in an unpaired high surrogate; both would serialise as "x�".
        PrivacyEngine engine = new(
            new PrivacyPolicy { DefaultAction = PrivacyAction.Remove },
            [new LowSurrogateDetector()]);

        PrivacyScanResult result = engine.RedactJson("{\"x\U0001F600\":1,\"x\U0001F900\":2}");

        Assert.True(result.Succeeded);
        Assert.StartsWith("{\"x\\uFFFD\":1,\"redacted-key-1\":2,", result.RedactedJson, StringComparison.Ordinal);
        AssertUniqueKeys(result.RedactedJson!);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    public void PrivacyEngine_RejectsFieldRuleWithoutSegments(string path)
    {
        PrivacyPolicy policy = new() { FieldRules = [new PrivacyFieldRule(path, PrivacyAction.Remove)] };

        ArgumentException error = Assert.Throws<ArgumentException>(() => new PrivacyEngine(policy));
        Assert.Equal($"Privacy field rule path '{path}' has no segments.", error.Message);
    }

    [Fact]
    public void PrivacyEngine_RejectsPoliciesThatWouldThrowOrFailOpen()
    {
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy { MaximumFieldLength = -1 }));
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy
        {
            FieldRules = [new PrivacyFieldRule("a", PrivacyAction.Truncate, -1)]
        }));
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy { ReplacementText = null! }));
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy { FieldRules = null! }));
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy { FieldRules = [null!] }));
        Assert.Throws<ArgumentException>(() => new PrivacyEngine(new PrivacyPolicy { DisabledDetectors = null! }));

        // Negative lengths on rules that never truncate stay accepted (profiles allow them).
        _ = new PrivacyEngine(new PrivacyPolicy { FieldRules = [new PrivacyFieldRule("a", PrivacyAction.Mask, -1)] });
        _ = new PrivacyEngine(new PrivacyPolicy { MaximumFieldLength = 0 });
    }

    [Fact]
    public void RedactJsonAndText_FailClosedWhenADetectorThrows()
    {
        PrivacyEngine engine = new(detectors: [new ThrowingDetector()]);

        PrivacyScanResult json = engine.RedactJson("""{"a":"x"}""");
        PrivacyTextResult text = engine.RedactText("x");

        Assert.False(json.Succeeded);
        Assert.Equal("redaction-failed", json.FailureCode);
        Assert.Null(json.RedactedJson);
        Assert.False(text.Succeeded);
        Assert.Equal("redaction-failed", text.FailureCode);
        Assert.Null(text.RedactedText);
    }

    [Fact]
    public void RedactJsonAndText_FailClosedWhenADetectorReportsOutOfRangeOffsets()
    {
        PrivacyEngine engine = new(detectors: [new OutOfRangeDetector()]);

        Assert.Equal("redaction-failed", engine.RedactJson("""{"a":"x"}""").FailureCode);
        Assert.Equal("redaction-failed", engine.RedactText("x").FailureCode);
    }

    [Theory]
    [InlineData("RSA PRIVATE KEY", "rsa-private")]
    [InlineData("EC PRIVATE KEY", "ecdsa-private")]
    [InlineData("DSA PRIVATE KEY", "dsa-private")]
    [InlineData("OPENSSH PRIVATE KEY", "openssh-private")]
    [InlineData("ENCRYPTED PRIVATE KEY", "encrypted-private")]
    [InlineData("PRIVATE KEY", "pkcs8-private")]
    [InlineData("CERTIFICATE", "x509-certificate")]
    [InlineData("PGP PRIVATE KEY BLOCK", "pgp-private")]
    [InlineData("PGP PUBLIC KEY BLOCK", "pgp-public")]
    [InlineData("PGP KEY BLOCK", "pgp")]
    public void CryptoMaterial_IsLabelledByItsExactHeader(string label, string kind)
    {
        // Body text naming other kinds never changes the label.
        PrivacyTextResult result = new PrivacyEngine().RedactText(
            $"-----BEGIN {label}-----\nRSA PRIVATE ECDSA PGP BEGIN SSH2\n-----END {label}-----");

        Assert.Equal(string.Empty, result.RedactedText);
        AppliedFinding finding = Assert.Single(result.Findings);
        Assert.Equal(DetectorIds.CryptoMaterial, finding.DetectorId);
        Assert.Equal(kind, finding.SubKind);
    }

    [Fact]
    public void Crn_IsAPatternMatchNotAValidatedChecksum()
    {
        PrivacyTextResult result = new PrivacyEngine().RedactText("CRN 123 456 789A");

        AppliedFinding crn = Assert.Single(result.Findings, finding => finding.DetectorId == DetectorIds.Crn);
        Assert.False(crn.Validated);
        Assert.Equal("CRN *****6789", result.RedactedText);
    }

    [Theory]
    [InlineData("licence 12345678", "NSW/VIC/QLD-like")]
    [InlineData("licence 1234567", "SA/TAS/WA-like")]
    [InlineData("licence AB123456", "ACT-like")]
    [InlineData("licence ab123456", "ACT-like")]
    [InlineData("licence 1234567890", "NT-like")]
    [InlineData("licence A1234567", "unknown")]
    public void DriverLicence_InfersStateBucket(string text, string state)
    {
        PrivacyTextResult result = new PrivacyEngine().RedactText(text);

        AppliedFinding licence = Assert.Single(result.Findings, finding => finding.DetectorId == DetectorIds.DriverLicence);
        Assert.Equal(state, licence.SubKind);
    }

    private static void AssertUniqueKeys(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            Assert.True(seen.Add(property.Name), $"duplicate key {property.Name}");
        }
    }

    private sealed class ThrowingRedactor : IEventRedactor
    {
        public RedactionResult Redact(string json) =>
            throw new System.Text.RegularExpressions.RegexMatchTimeoutException();
    }

    private sealed class ThrowingDetector : ISensitiveDetector
    {
        public string Id => "custom.throws";

        public string Category => "custom";

        public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches) =>
            throw new NotSupportedException("detector bug");
    }

    private sealed class OutOfRangeDetector : ISensitiveDetector
    {
        public string Id => "custom.out-of-range";

        public string Category => "custom";

        public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches) =>
            matches.Add(new DetectionMatch(Id, Category, text.Length, 5, Validated: true));
    }

    private sealed class LowSurrogateDetector : ISensitiveDetector
    {
        public string Id => "custom.low-surrogate";

        public string Category => "custom";

        public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
        {
            for (int index = 0; index < text.Length; index++)
            {
                if (char.IsLowSurrogate(text[index]))
                {
                    matches.Add(new DetectionMatch(Id, Category, index, 1, Validated: true));
                }
            }
        }
    }
}
