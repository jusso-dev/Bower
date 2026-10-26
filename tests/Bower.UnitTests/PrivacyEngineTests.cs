using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Redaction;
using Bower.Redaction.Privacy;
using Bower.Redaction.Validation;

namespace Bower.UnitTests;

public sealed class ChecksumAlgorithmsTests
{
    [Theory]
    [InlineData("100000001", true)]
    [InlineData("123456789", false)]
    public void Tfn_Checksum(string digits, bool expected)
    {
        Assert.Equal(expected, ChecksumAlgorithms.IsValidTfn(digits));
    }

    [Fact]
    public void Tfn_AcceptsEightDigitWhenPaddedValid()
    {
        // Known-valid 9-digit TFN; 8-digit form is accepted via leading-zero pad path
        // when the padded value satisfies the ATO algorithm.
        Assert.True(ChecksumAlgorithms.IsValidTfn("100000001"));
        // Synthetic 8-digit: engine pads to 9 with leading zero before checksum.
        // 086001002 → verify via direct 9-digit with leading zero if valid.
        for (int n = 0; n < 1_000_000; n++)
        {
            string eight = n.ToString("D8", System.Globalization.CultureInfo.InvariantCulture);
            string nine = "0" + eight;
            if (!ChecksumAlgorithms.IsValidTfn(nine.AsSpan()))
            {
                continue;
            }

            Assert.True(ChecksumAlgorithms.IsValidTfn(eight.AsSpan()));
            return;
        }

        Assert.Fail("No valid 8-digit TFN found in search window");
    }

    [Theory]
    [InlineData("51824753556", true)]
    [InlineData("51824753557", false)]
    public void Abn_Checksum(string digits, bool expected)
    {
        Assert.Equal(expected, ChecksumAlgorithms.IsValidAbn(digits));
    }

    [Theory]
    [InlineData("000000019", true)]
    [InlineData("000000018", false)]
    public void Acn_Checksum(string digits, bool expected)
    {
        Assert.Equal(expected, ChecksumAlgorithms.IsValidAcn(digits));
    }

    [Theory]
    [InlineData("2123456701", true)]
    [InlineData("2123456711", false)] // wrong check digit (pos 9); issue digit still 1
    public void Medicare_Checksum(string digits, bool expected)
    {
        Assert.Equal(expected, ChecksumAlgorithms.IsValidMedicare(digits));
    }

    [Theory]
    [InlineData("8003600000000007", true)]
    [InlineData("8003600000000008", false)]
    public void Ihi_Checksum(string digits, bool expected)
    {
        Assert.Equal(expected, ChecksumAlgorithms.IsValidIhi(digits));
    }

    [Fact]
    public void Luhn_VisaTestPan()
    {
        Assert.True(ChecksumAlgorithms.Luhn("4111111111111111"));
        Assert.False(ChecksumAlgorithms.Luhn("4111111111111112"));
    }
}

public sealed class PrivacyEngineTests
{
    [Fact]
    public void RedactJson_DetectsAustralianIdentifiersWithChecksum()
    {
        const string json =
            """
            {
              "tfn": "100000001",
              "abn": "51 824 753 556",
              "medicare": "2123 45670 1",
              "ihi": "8003600000000007",
              "crn": "123 456 789A"
            }
            """;

        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Tfn && f.Validated);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Abn && f.Validated);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Medicare && f.Validated);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Ihi && f.Validated);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Crn);
        Assert.DoesNotContain("100000001", result.RedactedJson);
        Assert.Contains("*****0001", result.RedactedJson, StringComparison.Ordinal);
        Assert.True(result.Metadata.HasFindings);
        // An unkeyed hash of a TFN is reversible by enumeration, so the default masks.
        Assert.Equal("Masked", result.Metadata.Actions[DetectorIds.Tfn]);
        Assert.Equal("Allow", result.Metadata.Actions[DetectorIds.Abn]);
    }

    [Fact]
    public void RedactJson_RejectsInvalidTfnChecksum()
    {
        const string json = """{ "tfn": "123456789" }""";
        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(result.Findings, f => f.DetectorId == DetectorIds.Tfn);
        Assert.Contains("123456789", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_RemovesSecretsAndJwt()
    {
        const string json =
            """
            {
              "awsKey": "AKIAIOSFODNN7EXAMPLE",
              "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
              "password": "do-not-store",
              "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
            }
            """;

        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result.RedactedJson);
        Assert.DoesNotContain("do-not-store", result.RedactedJson);
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result.RedactedJson);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", result.RedactedJson);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Aws);
        Assert.Contains(result.Findings, f => f.DetectorId is DetectorIds.Jwt or DetectorIds.Entra);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.CryptoMaterial);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.FieldNameSecret);
    }

    [Fact]
    public void RedactJson_RemovesCreditCardByDefault()
    {
        const string json = """{ "pan": "4111111111111111" }""";
        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(json);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.CreditCard && f.Validated);
        Assert.DoesNotContain("4111111111111111", result.RedactedJson);
        Assert.Equal("Removed", result.Metadata.Actions[DetectorIds.CreditCard]);
    }

    [Fact]
    public void RedactJson_MasksCreditCardWhenConfigured()
    {
        PrivacyPolicy policy = PrivacyPolicy.CreateDefault();
        Dictionary<string, PrivacyAction> actions = new(policy.DetectorActions)
        {
            [DetectorIds.CreditCard] = PrivacyAction.Mask
        };
        policy = new PrivacyPolicy
        {
            DefaultAction = policy.DefaultAction,
            DetectorActions = actions,
            EmitMetadata = true
        };

        PrivacyEngine engine = new(policy);
        PrivacyScanResult result = engine.RedactJson("""{ "pan": "4111111111111111" }""");

        Assert.Contains("****-****-****-1111", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_CardWithHugeSeparatorRunDoesNotExhaustStack()
    {
        // The card pattern allows unbounded separators between digits, so a match can be
        // nearly the whole value. Digit extraction must not stack-allocate its length.
        string pan = "4" + new string('-', 600_000) + "111111111111111";
        PrivacyEngine engine = new();

        PrivacyScanResult result = engine.RedactJson(JsonSerializer.Serialize(new { pan }));

        Assert.True(result.Succeeded);
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.CreditCard);
        Assert.DoesNotContain("111111111111111", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_DenseValueRedactsEveryFindingInPlace()
    {
        // 2,000 findings in one value, kept under the 32 KiB field-length limit so the
        // result is not truncated.
        string[] emails = Enumerable.Range(0, 2_000).Select(index => $"u{index}@ex.io").ToArray();
        PrivacyEngine engine = new();

        PrivacyScanResult result = engine.RedactJson(
            JsonSerializer.Serialize(new { note = string.Join(" | ", emails) }));

        Assert.True(result.Succeeded);
        Assert.Equal(2_000, result.Findings.Count(f => f.DetectorId == DetectorIds.Email));
        string note = JsonDocument.Parse(result.RedactedJson!).RootElement.GetProperty("note").GetString()!;
        Assert.Equal(string.Join(" | ", emails.Select(email => "u***" + email[email.IndexOf('@')..])), note);
    }

    [Fact]
    public void RedactJson_OverlappingFindingsKeepLongestSpan()
    {
        // A JWT is also a Kubernetes token shape; exactly one detector must own the span.
        const string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        PrivacyEngine engine = new();

        PrivacyScanResult result = engine.RedactJson($$"""{ "note": "before {{jwt}} after a@ex.io" }""");

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(jwt, result.RedactedJson);
        Assert.Contains("before  after a***@ex.io", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_MasksEmail()
    {
        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson("""{ "owner": "alice@example.test" }""");

        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.Email);
        Assert.Contains("a***@example.test", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_DetectsApiKeysByProvider()
    {
        const string json =
            """
            {
              "openai": "sk-abcdefghijklmnopqrstuvwxyz12",
              "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
              "stripe": "sk_live_abcdefghijklmnopqrstuv"
            }
            """;

        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(json);

        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.ApiKey && f.SubKind == "OpenAI");
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.ApiKey && f.SubKind == "GitHub");
        Assert.Contains(result.Findings, f => f.DetectorId == DetectorIds.ApiKey && f.SubKind == "Stripe");
    }

    [Fact]
    public void BuiltInDetectorPatterns_HaveNoWallClockTimeout()
    {
        // A match timeout makes the redaction outcome depend on machine load: 50 ms
        // timeouts on the API key patterns quarantined a valid 60,000-character value
        // under CI load. Built-in patterns are linear and inputs are bounded by
        // MaximumPayloadBytes instead, as in the Rust engine (which has no timeouts).
        MethodInfo[] factories =
        [
            .. typeof(PrivacyEngine).Assembly.GetTypes()
                .SelectMany(type => type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                .Where(method => method.IsDefined(typeof(GeneratedRegexAttribute), inherit: false))
        ];

        string[] timed =
        [
            .. factories
                .Where(method => ((Regex)method.Invoke(null, null)!).MatchTimeout != Regex.InfiniteMatchTimeout)
                .Select(method => $"{method.DeclaringType!.Name}.{method.Name}")
        ];

        Assert.True(factories.Length > 40, $"Expected the built-in detector patterns, found {factories.Length}.");
        Assert.Empty(timed);
    }

    [Fact]
    public void RedactJson_RespectsDisabledDetector()
    {
        PrivacyPolicy policy = new PrivacyPolicy
        {
            DefaultAction = PrivacyAction.Mask,
            DetectorActions = PrivacyPolicy.CreateDefault().DetectorActions,
            DisabledDetectors = new HashSet<string> { DetectorIds.Email },
            EmitMetadata = true
        };

        PrivacyEngine engine = new(policy);
        PrivacyScanResult result = engine.RedactJson("""{ "owner": "alice@example.test" }""");

        Assert.DoesNotContain(result.Findings, f => f.DetectorId == DetectorIds.Email);
        Assert.Contains("alice@example.test", result.RedactedJson);
    }

    [Fact]
    public void RedactJson_EmitsPrivacyMetadataWithoutOriginals()
    {
        PrivacyEngine engine = new();
        PrivacyScanResult result = engine.RedactJson(
            """{ "tfn": "100000001", "email": "bob@example.test" }""");

        Assert.NotNull(result.RedactedJson);
        using JsonDocument doc = JsonDocument.Parse(result.RedactedJson);
        Assert.True(doc.RootElement.TryGetProperty("privacy", out JsonElement privacy));
        Assert.True(privacy.TryGetProperty("detected", out _));
        Assert.True(privacy.TryGetProperty("actions", out _));
        Assert.DoesNotContain("100000001", result.RedactedJson);
        string privacyJson = privacy.GetRawText();
        Assert.DoesNotContain("100000001", privacyJson);
        Assert.DoesNotContain("bob@example.test", privacyJson);
    }

    [Fact]
    public void RedactText_WorksForNonJsonSources()
    {
        PrivacyEngine engine = new();
        PrivacyTextResult result = engine.RedactText(
            "user email alice@example.test pan 4111111111111111");

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("4111111111111111", result.RedactedText);
        Assert.Contains("a***@example.test", result.RedactedText);
    }

    [Fact]
    public void JsonEventRedactor_StillImplementsIEventRedactor()
    {
        JsonEventRedactor redactor = new();
        Bower.Abstractions.RedactionResult result = redactor.Redact(
            """{ "actor": { "email": "alice@example.test", "password": "x" } }""");

        Assert.True(result.Succeeded);
        Assert.Contains("$.actor.password", result.RemovedPaths);
        Assert.Contains("a***@example.test", result.RedactedJson);
    }

    [Fact]
    public void DetectorCatalog_RegistersAllModules()
    {
        IReadOnlyList<ISensitiveDetector> detectors = DetectorCatalog.CreateDefaultValueDetectors();
        Assert.True(detectors.Count >= 30);
        Assert.Contains(detectors, d => d.Id == DetectorIds.Tfn);
        Assert.Contains(detectors, d => d.Id == DetectorIds.ApiKey);
        Assert.Contains(detectors, d => d.Id == DetectorIds.CryptoMaterial);
    }
}
