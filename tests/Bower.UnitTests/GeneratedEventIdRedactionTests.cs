using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// Bower-generated record ids (lowercase SHA-256 digests) skip content detectors only when
/// the caller proves Bower computed them; source text is always scanned. The Rust port pins
/// the same vectors (rust/crates/bower-redaction/tests/generated_event_id.rs).
/// </summary>
public sealed class GeneratedEventIdRedactionTests
{
    // Passes the IBAN mod-97 check ("dd" + "97" + 28 alphanumerics): the native pilot false positive.
    private const string IbanLikeId = "winevt-dd97c1d25d12d2e202c1e010d70d55f4";
    private const string OtherIbanLikeId = "syslog-ef23e985944885bb7eee3f74b9a4872f";

    // Operators add detectors like this for generic hex API keys; it matches every record id.
    private static readonly PrivacyPolicy HexDetectorPolicy = PrivacyProfileLoader.Load("""
        apiVersion: bower.security/v1
        kind: PrivacyProfile
        metadata:
          id: hex-digest-test
          version: 1.0.0
        customDetectors:
          - id: custom.hex-digest
            pattern: '[0-9a-f]{32}'
            action: mask
            tests:
              match: ['0123456789abcdef0123456789abcdef']
        """, new byte[32], "k1").Policy;

    private static JsonObject Redact(string json, string? generatedEventId)
    {
        PrivacyScanResult result = new PrivacyEngine(HexDetectorPolicy).RedactJson(json, new RedactionContext(generatedEventId));
        Assert.True(result.Succeeded);
        return JsonNode.Parse(result.RedactedJson!)!.AsObject();
    }

    [Fact]
    public void WithoutProof_AHexDetectorMasksTheGeneratedId()
    {
        const string customOnlyId = "winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        JsonObject redacted = Redact($$"""{"eventId":"{{customOnlyId}}"}""", null);
        Assert.NotEqual(customOnlyId, redacted["eventId"]!.GetValue<string>());
        Assert.Contains("custom.hex-digest", redacted["privacy"]!["detected"]!.AsArray().Select(item => item!.GetValue<string>()));
    }

    [Fact]
    public void DefaultPolicy_RetainsConservativeIbanDetection()
    {
        PrivacyEngine engine = new();
        foreach (string iban in new[] { "GB82WEST12345698765432", "gb82west12345698765432", "DE89370400440532013000",
            "FR1420041010050500013M02606", "NL91ABNA0417164300", "MT84MALT011000012345MTLCAST001S",
            "XX57WEST12345698765432", "GB04WEST123456987654" })
        {
            Assert.DoesNotContain(iban, engine.RedactJson($$"""{"note":"pay {{iban}} today"}""").RedactedJson, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void GeneratedId_KeepsBothIdentityFieldsWhileEverySourceFieldIsStillRedacted()
    {
        JsonObject redacted = Redact($$"""
            {"eventId":"{{IbanLikeId}}","eventOriginalId":"{{IbanLikeId}}",
             "request":{"correlationId":"{{IbanLikeId}}"},
             "attributes":{"eventId":"{{IbanLikeId}}","card":"4111111111111111",
               "iban":"GB82WEST12345698765432","note":"key AKIAIOSFODNN7EXAMPLE" },
             "labels":{"ids":["{{IbanLikeId}}"]} }
            """, IbanLikeId);

        Assert.Equal(IbanLikeId, redacted["eventId"]!.GetValue<string>());
        Assert.Equal(IbanLikeId, redacted["eventOriginalId"]!.GetValue<string>());
        // Only the two root identity fields are exempt; equal text elsewhere is source data.
        Assert.NotEqual(IbanLikeId, redacted["request"]!["correlationId"]!.GetValue<string>());
        Assert.NotEqual(IbanLikeId, redacted["attributes"]!["eventId"]!.GetValue<string>());
        Assert.NotEqual(IbanLikeId, redacted["labels"]!["ids"]![0]!.GetValue<string>());
        string text = redacted.ToJsonString();
        Assert.DoesNotContain("4111111111111111", text, StringComparison.Ordinal);
        Assert.DoesNotContain("GB82WEST12345698765432", text, StringComparison.Ordinal);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ADifferentValueInTheIdentityField_IsScannedEvenWhenItIsAlsoWellFormed()
    {
        JsonObject redacted = Redact($$"""{"eventId":"{{OtherIbanLikeId}}","eventOriginalId":"{{IbanLikeId}}"}""", IbanLikeId);
        Assert.NotEqual(OtherIbanLikeId, redacted["eventId"]!.GetValue<string>());
        Assert.Equal(IbanLikeId, redacted["eventOriginalId"]!.GetValue<string>());
    }

    [Theory]
    // Secrets or identifiers that a caller might wrongly claim as generated: never exempt.
    [InlineData("4111111111111111")]
    [InlineData("syslog-4111111111111111")]
    [InlineData("syslog-4111 1111 1111 1111 0000 0000 0000 0000")]
    [InlineData("AKIAIOSFODNN7EXAMPLE")]
    [InlineData("GB82WEST12345698765432")]
    [InlineData("WINEVT-dd97c1d25d12d2e202c1e010d70d55f4")]
    [InlineData("winevt-DD97C1D25D12D2E202C1E010D70D55F4")]
    [InlineData("winevt-dd97c1d25d12d2e202c1e010d70d55f")]
    [InlineData("winevt-dd97c1d25d12d2e202c1e010d70d55f4a")]
    [InlineData("winevt-dd97c1d25d12d2e202c1e010d70d55g4")]
    [InlineData("-dd97c1d25d12d2e202c1e010d70d55f4")]
    [InlineData("abcdefghijklmnopq-dd97c1d25d12d2e202c1e010d70d55f4")]
    [InlineData("win-evt-dd97c1d25d12d2e202c1e010d70d55f")]
    [InlineData("")]
    public void MalformedClaims_ExemptNothing(string claimed)
    {
        Assert.False(GeneratedEventIds.IsWellFormed(claimed));
        PrivacyEngine engine = new(HexDetectorPolicy);
        string json = new JsonObject { ["eventId"] = claimed, ["eventOriginalId"] = IbanLikeId }.ToJsonString();
        Assert.Equal(engine.RedactJson(json).RedactedJson, engine.RedactJson(json, new RedactionContext(claimed)).RedactedJson);
    }

    [Theory]
    [InlineData(IbanLikeId)]
    [InlineData(OtherIbanLikeId)]
    [InlineData("aws-0123456789abcdef0123456789abcdef")]
    public void IsWellFormed_AcceptsOnlyAPrefixAndThirtyTwoLowercaseHexCharacters(string id) =>
        Assert.True(GeneratedEventIds.IsWellFormed(id));

    [Fact]
    public void FieldRulesAndLengthLimits_StillApplyToAGeneratedId()
    {
        PrivacyPolicy policy = new() { FieldRules = [new PrivacyFieldRule("eventId", PrivacyAction.Sha256)] };
        PrivacyScanResult result = new PrivacyEngine(policy).RedactJson($$"""{"eventId":"{{IbanLikeId}}"}""", new RedactionContext(IbanLikeId));
        Assert.DoesNotContain(IbanLikeId, result.RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void ProcessorAndRedactorWrappers_ForwardTheProofAndDefaultToScanning()
    {
        IEventRedactor wrapped = new Bower.Redaction.JsonEventRedactor(HexDetectorPolicy);
        string json = $$"""{"eventId":"{{IbanLikeId}}"}""";
        Assert.Contains(IbanLikeId, wrapped.Redact(json, new RedactionContext(IbanLikeId)).RedactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain(IbanLikeId, wrapped.Redact(json).RedactedJson, StringComparison.Ordinal);
        // A redactor that does not implement the overload scans everything.
        IEventRedactor legacy = new ScanEverything();
        Assert.DoesNotContain(IbanLikeId, legacy.Redact(json, new RedactionContext(IbanLikeId)).RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public void GeneratedId_DoesNotExemptNumbersOrStringsFromDetectors()
    {
        // Counters of a Bower-built record (for example collector_health). 8-16 digit numbers
        // pass card, TFN, ABN or Medicare checksums often enough to be masked by default.
        const string record = """
            {"eventId":"health-0123456789abcdef0123456789abcdef","attributes":{"queue":{"queued":14804099,
             "bytes":2693848688944172,"ratio":323600851.5},"counts":[4111111111111111,3605917251],
             "label":"4111111111111111","note":"card 4111 1111 1111 1111"} }
            """;
        PrivacyEngine engine = new();
        const string id = "health-0123456789abcdef0123456789abcdef";
        JsonObject redacted = JsonNode.Parse(engine.RedactJson(record, new RedactionContext(id)).RedactedJson!)!.AsObject();
        Assert.Equal(id, redacted["eventId"]!.GetValue<string>());
        JsonNode attributes = redacted["attributes"]!;
        Assert.Equal(System.Text.Json.JsonValueKind.String, attributes["counts"]![0]!.GetValueKind());
        Assert.NotEqual("4111111111111111", attributes["label"]!.GetValue<string>());
        Assert.DoesNotContain("4111 1111 1111 1111", redacted.ToJsonString(), StringComparison.Ordinal);
    }

    private sealed class ScanEverything : IEventRedactor
    {
        public RedactionResult Redact(string json) => new PrivacyEngine(HexDetectorPolicy).RedactJson(json).ToRedactionResult();
    }
}
