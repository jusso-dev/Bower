using System.Text.Json;
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
        Assert.Contains("sha256:", result.RedactedJson, StringComparison.Ordinal);
        Assert.True(result.Metadata.HasFindings);
        Assert.Equal("SHA256", result.Metadata.Actions[DetectorIds.Tfn]);
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
              "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
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
