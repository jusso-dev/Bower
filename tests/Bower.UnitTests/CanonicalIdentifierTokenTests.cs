using System.Text.Json.Nodes;
using Bower.Redaction.Detectors.Australian;
using Bower.Redaction.Detectors.Financial;
using Bower.Redaction.Privacy;
using Bower.Redaction.Validation;

namespace Bower.UnitTests;

/// <summary>
/// Structured number detectors (TFN, card, IBAN and the like) never claim a span wholly inside
/// a canonical UUID or dashless GUID token, so random producer event ids are not redacted (and
/// then quarantined as <c>event-id-redacted</c>), while real identifiers in text still are.
/// The Rust port pins the same cases (rust/crates/bower-redaction/tests/canonical_identifier.rs).
/// </summary>
public sealed class CanonicalIdentifierTokenTests
{
    private const int Samples = 200_000;

    // First group passes the TFN checksum (the CollectorHostTests ids before this rule).
    private const string TfnFirstGroupUuid = "10040680-c19c-4eec-8ca0-056e33f7f420";

    private static readonly PrivacyPolicy OptIn = new()
    {
        DetectorActions = new Dictionary<string, PrivacyAction>(PrivacyPolicy.CreateDefault().DetectorActions, StringComparer.Ordinal),
        EnabledOptInDetectors = new HashSet<string>(
            [DetectorIds.IpAddress, DetectorIds.Hostname, DetectorIds.Username, DetectorIds.Address, DetectorIds.Gps, DetectorIds.SecurityMarking],
            StringComparer.Ordinal)
    };

    public static TheoryData<string> Shapes => ["dashed", "dashed-upper", "dashless", "dashless-upper", "braced", "v7-digits"];

    [Theory]
    [MemberData(nameof(Shapes))]
    public void RandomIdentifiers_AreNeverAlteredAsEventIdsOrInText(string shape)
    {
        Random random = new(20261107);
        PrivacyEngine defaults = new();
        PrivacyEngine optIn = new(OptIn);
        int rawDetectorHits = 0;
        int altered = 0;
        for (int sample = 0; sample < Samples; sample++)
        {
            string id = Identifier(random, shape);
            rawDetectorHits += RawStructuredHits(id);
            string eventJson = $$"""{"eventId":"{{id}}"}""";
            altered += Altered(defaults, eventJson, id);
            if (sample % 10 == 0)
            {
                // Opt-in detectors add no structured number detector; sampled to bound run time.
                string text = $$"""{"message":"request {{id}} failed (ref={{id}}); retry \"{{id}}\"","ids":["{{id}}"]}""";
                altered += Altered(optIn, eventJson, id) + Altered(defaults, text, id) + Altered(optIn, text, id);
            }
        }

        // The corpus exercises the defect: the detectors alone still fire on these ids.
        Assert.True(rawDetectorHits > 50, $"{shape}: only {rawDetectorHits} raw detector hits");
        Assert.Equal(0, altered);
    }

    // ABNs are public business numbers and allowed by default, so they are not listed.
    public static TheoryData<string> RealIdentifiers =>
    [
        "123456782", "123 456 782", "123-456-782", "10040680", "000 000 019",
        "2123456701", "2123 45670 1", "8003600000000007", "4111111111111111", "4111 1111 1111 1111",
        "4111-1111-1111-1111", "5555555555554444", "378282246310005", "GB82WEST12345698765432",
        "gb82west12345698765432", "DE89370400440532013000", "NL91ABNA0417164300", "FR1420041010050500013M02606"
    ];

    // Contexts a real identifier is written in, including next to UUID-like fragments.
    private static readonly string[] Contexts =
    [
        "{0}", "value {0} end", "TFN {0}", "TFN:{0}", "x-{0}", "{0}-x", "-{0}-", "\\\"{0}\\\"", "'{0}'", "({0})", "[{0}]",
        "{{{0}}}", "<{0}>", "id={0};", "{0}.", ",{0},", "/{0}/", "ref:{0}", "{0}\\n", "#{0}", "{0}-c19c-4eec-8ca0",
        "{0}-c19c-4eec-8ca0-056e33f7f420-0", "c19c-{0}", "{0} c19c-4eec-8ca0-056e33f7f420", "urn:uuid:{0}",
        "3f2a9c1e-c19c-4eec-8ca0-056e33f7f420 {0}", "{0}/3f2a9c1e-c19c-4eec-8ca0-056e33f7f420"
    ];

    [Theory]
    [MemberData(nameof(RealIdentifiers))]
    public void RealIdentifiers_InTextAndNextToPunctuation_AreStillRedacted(string identifier)
    {
        Assert.True(IsChecksumValid(identifier), identifier);
        foreach (PrivacyEngine engine in new[] { new PrivacyEngine(), new PrivacyEngine(OptIn) })
        {
            foreach (string context in Contexts)
            {
                string text = string.Format(System.Globalization.CultureInfo.InvariantCulture, context, identifier);
                PrivacyScanResult result = engine.RedactJson($$"""{"eventId":"{{text}}","message":"{{text}}"}""");
                Assert.True(result.Succeeded);
                Assert.DoesNotContain(identifier, result.RedactedJson, StringComparison.Ordinal);
            }
        }
    }

    public static TheoryData<string> NearIdentifiers =>
    [
        "TFN-10040680-c19c-4eec-8ca0-056e33f7f420", // prefix joins the token
        "10040680-c19c-4eec-8ca0-056e33f7f420x",
        "10040680-c19c-4eec-8ca0-056e33f7f4200",
        "10040680-c19c-4eec-8ca0-056e33f7f42",
        "10040680-c19c-4eec-8ca0-056e33f7f42g",
        "10040680-c19c-4eec-8ca0_056e33f7f420",
        "10040680-c19c4eec-8ca0-056e33f7f420",
        "10040680 c19c-4eec-8ca0-056e33f7f420",
        "10040680-c19c-4eec-8ca0-056e33f7f420_",
        "a-10040680-c19c-4eec-8ca0-056e33f7f420",
        "4111111111111111-c19c-4eec-8ca0-056e33f7f420",
        "123456782-c19c-4eec-8ca0-056e33f7f420",
    ];

    [Theory]
    [MemberData(nameof(NearIdentifiers))]
    public void NearCanonicalShapes_GetNoExemption(string value)
    {
        Assert.Empty(CanonicalIdentifierTokens.Find(value));
        string redacted = new PrivacyEngine().RedactJson($$"""{"eventId":"{{value}}"}""").RedactedJson!;
        Assert.NotEqual(value, JsonNode.Parse(redacted)!["eventId"]!.GetValue<string>());
    }

    /// <summary>
    /// Accepted limit, documented in docs/privacy/privacy-secret-engine.md: a producer that
    /// deliberately writes an eight-digit TFN as the first group of a UUID is not caught. A
    /// producer that wants to leak data can always encode it; redaction stops accidental
    /// disclosure, and no person writes a TFN, card or IBAN as a UUID.
    /// </summary>
    [Fact]
    public void AttackerChosenUuidWithTfnFirstGroup_IsAnIdentifierNotATfn()
    {
        Assert.True(ChecksumAlgorithms.IsValidTfn("10040680"));
        foreach (string id in new[] { "10040680-0000-0000-0000-000000000000", TfnFirstGroupUuid, "{" + TfnFirstGroupUuid + "}" })
        {
            string redacted = new PrivacyEngine().RedactJson($$"""{"eventId":"{{id}}"}""").RedactedJson!;
            Assert.Equal(id, JsonNode.Parse(redacted)!["eventId"]!.GetValue<string>());
        }

        // The same eight digits anywhere else are still a TFN.
        Assert.DoesNotContain("10040680", new PrivacyEngine().RedactJson("""{"note":"TFN 10040680 c19c"}""").RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void SecretAndCustomDetectors_StillScanIdentifierTokens()
    {
        const string guid = "dd97c1d25d12d2e202c1e010d70d55f4";
        Assert.DoesNotContain(guid, new PrivacyEngine().RedactJson($$"""{"note":"datadog api_key {{guid}}"}""").RedactedJson, StringComparison.Ordinal);

        PrivacyPolicy hex = PrivacyProfileLoader.Load("""
            apiVersion: bower.security/v1
            kind: PrivacyProfile
            metadata:
              id: uuid-test
              version: 1.0.0
            customDetectors:
              - id: custom.uuid
                pattern: '[0-9a-f]{8}-[0-9a-f]{4}'
                action: mask
                tests:
                  match: ['10040680-c19c']
            """, new byte[32], "k1").Policy;
        Assert.DoesNotContain(TfnFirstGroupUuid, new PrivacyEngine(hex).RedactJson($$"""{"eventId":"{{TfnFirstGroupUuid}}"}""").RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Find_ReturnsBoundedTokensOnly()
    {
        string text = "a " + TfnFirstGroupUuid + ", {DD97C1D25D12D2E202C1E010D70D55F4} é" + TfnFirstGroupUuid + " x" + TfnFirstGroupUuid;
        List<(int Start, int End)> tokens = CanonicalIdentifierTokens.Find(text);
        Assert.Equal([(2, 38), (41, 73), (76, 112)], tokens);
        Assert.False(CanonicalIdentifierTokens.IsCanonicalIdentifier("10040680-c19c-4eec-8ca0-056e33f7f42-"));
        Assert.False(CanonicalIdentifierTokens.IsCanonicalIdentifier("dd97c1d25d12d2e202c1e010d70d55f"));
        Assert.False(CanonicalIdentifierTokens.IsCanonicalIdentifier("GB82WEST12345698765432aaaaaaaaaa"));
        Assert.True(CanonicalIdentifierTokens.IsCanonicalIdentifier("00000000-0000-0000-0000-000000000000"));
        Assert.DoesNotContain(DetectorIds.PayId, (IReadOnlySet<string>)CanonicalIdentifierTokens.StructuredNumberDetectorIds);
        Assert.DoesNotContain(DetectorIds.ApiKey, (IReadOnlySet<string>)CanonicalIdentifierTokens.StructuredNumberDetectorIds);
    }

    private static int Altered(PrivacyEngine engine, string json, string id)
    {
        PrivacyScanResult result = engine.RedactJson(json);
        Assert.True(result.Succeeded);
        return result.Findings.Count == 0 && result.RedactedJson!.Contains(id, StringComparison.Ordinal) ? 0 : 1;
    }

    private static int RawStructuredHits(string id)
    {
        List<DetectionMatch> matches = [];
        new TfnDetector().Detect(id, "$", matches);
        new CreditCardDetector().Detect(id, "$", matches);
        new IbanDetector().Detect(id, "$", matches);
        return matches.Count;
    }

    private static bool IsChecksumValid(string identifier)
    {
        List<DetectionMatch> matches = [];
        foreach (ISensitiveDetector detector in DetectorCatalog.CreateDefaultValueDetectors())
        {
            if (CanonicalIdentifierTokens.StructuredNumberDetectorIds.Contains(detector.Id))
            {
                detector.Detect(identifier, "$", matches);
            }
        }

        return matches.Exists(match => match.Validated && match.Length == identifier.Length);
    }

    /// <summary>Random version 4 ids, and version 7 ids from 2024-08 to 2025-12 whose first group is all digits.</summary>
    internal static string Identifier(Random random, string shape)
    {
        byte[] bytes = new byte[16];
        if (shape == "v7-digits")
        {
            long from = new DateTimeOffset(2024, 8, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
            long to = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
            do
            {
                random.NextBytes(bytes);
                long milliseconds = random.NextInt64(from, to);
                for (int index = 0; index < 6; index++)
                {
                    bytes[index] = (byte)(milliseconds >> (8 * (5 - index)));
                }
            }
            while (!Convert.ToHexStringLower(bytes, 0, 4).All(char.IsAsciiDigit));

            bytes[6] = (byte)((bytes[6] & 0x0F) | 0x70);
        }
        else
        {
            random.NextBytes(bytes);
            bytes[6] = (byte)((bytes[6] & 0x0F) | 0x40);
        }

        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        string hex = Convert.ToHexStringLower(bytes);
        string dashed = $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
        return shape switch
        {
            "dashed" or "v7-digits" => dashed,
            "dashed-upper" => dashed.ToUpperInvariant(),
            "dashless" => hex,
            "dashless-upper" => hex.ToUpperInvariant(),
            "braced" => "{" + dashed + "}",
            _ => throw new ArgumentOutOfRangeException(nameof(shape))
        };
    }
}
