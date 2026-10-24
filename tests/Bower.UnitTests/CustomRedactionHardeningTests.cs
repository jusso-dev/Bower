using System.Text.Json.Nodes;
using Bower.Redaction.Detectors;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// Council round 1 engine findings (A1-A6). Ported to
/// rust/crates/bower-redaction/tests/custom_redaction_hardening.rs; byte parity is proven by
/// the generated vectors.
/// </summary>
public sealed class CustomRedactionHardeningTests
{
    private const string Header = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n";

    private const string TraceSample =
        """{"msg":"trace: card 4111111111111111 key AKIAIOSFODNN7EXAMPLE mail alice@example.test"}""";

    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

    private static string Detector(
        string id = "custom.d",
        string pattern = "x",
        string action = "mask",
        string extra = "",
        string tests = "[x]") =>
        $"customDetectors:\n  - id: {id}\n    pattern: '{pattern}'\n    action: {action}\n{extra}    tests:\n      match: {tests}\n";

    private static LoadedPrivacyProfile Load(string yaml) => PrivacyProfileLoader.Load(yaml, Key, "k1");

    private static PrivacyEngine Engine(string body) => new(Load(Header + body).Policy);

    private static string LoadError(string yaml) =>
        Assert.Throws<InvalidDataException>(() => Load(yaml)).Message;

    // ------------------------------------------------------------------ A1

    [Fact]
    public void AlertOnlyCustomDetector_DoesNotSuppressOtherDetectors()
    {
        PrivacyEngine engine = Engine(Detector(id: "custom.trace-line", pattern: "trace: .+", action: "alert-only", tests: "['trace: x']"));

        PrivacyScanResult result = engine.RedactJson(TraceSample);
        string message = JsonNode.Parse(result.RedactedJson!)!["msg"]!.GetValue<string>();

        Assert.Equal("trace: card  key  mail a***@example.test", message);
        Assert.Contains(result.Findings, finding => finding.DetectorId == "custom.trace-line" && finding.Action == PrivacyAction.AlertOnly);
        Assert.Contains("fin.credit-card:Visa", result.Metadata.Detected);
        Assert.Contains(result.Metadata.Detected, PrivacyEngine.IsSecurityEventWorthy);
        Assert.Equal("AlertOnly", result.Metadata.Actions["custom.trace-line"]);
    }

    [Fact]
    public void CustomDetectorAllowOverride_DoesNotClaimSpans()
    {
        CustomDetectorDefinition trace = CustomDetectorDefinition.Create("custom.trace-line", "trace: .+", PrivacyAction.Mask);
        PrivacyPolicy policy = new()
        {
            DetectorActions = new Dictionary<string, PrivacyAction>(PrivacyPolicy.CreateDefault().DetectorActions, StringComparer.Ordinal)
            {
                ["custom.trace-line"] = PrivacyAction.Allow
            },
            CustomDetectors = [trace]
        };

        PrivacyScanResult result = new PrivacyEngine(policy).RedactJson(TraceSample);

        Assert.Equal(
            "trace: card  key  mail a***@example.test",
            JsonNode.Parse(result.RedactedJson!)!["msg"]!.GetValue<string>());
        Assert.Contains(result.Findings, finding => finding.DetectorId == "custom.trace-line" && finding.Action == PrivacyAction.Allow);
    }

    [Fact]
    public void Load_RejectsAllowForCustomDetectors()
    {
        Assert.Equal(
            "Custom detector 'custom.d' cannot use action allow; use alert-only to record matches without redacting.",
            LoadError(Header + Detector(action: "Allow")));
    }

    [Fact]
    public void RedactingCustomDetectors_StillClaimTheirSpans()
    {
        PrivacyEngine engine = Engine(Detector(id: "custom.trace-line", pattern: "trace: .+", action: "replace", tests: "['trace: x']"));

        Assert.Equal(
            "***REDACTED***",
            JsonNode.Parse(engine.RedactJson(TraceSample).RedactedJson!)!["msg"]!.GetValue<string>());
    }

    // ------------------------------------------------------------------ A2

    [Fact]
    public void ValuesLongerThanTheScanLimit_QuarantineWhileCustomDetectorsAreEnabled()
    {
        string body = Detector(pattern: "EMP-\\d{6}", tests: "[EMP-123456]");
        string atLimit = "{\"a\":\"" + new string('x', CustomPatternDetector.MaximumScannedLength) + "\"}";
        string overLimit = "{\"a\":\"" + new string('x', CustomPatternDetector.MaximumScannedLength + 1) + "\"}";
        string longKey = "{\"" + new string('k', CustomPatternDetector.MaximumScannedLength + 1) + "\":1}";

        Assert.True(Engine(body).RedactJson(atLimit).Succeeded);
        Assert.Equal("redaction-failed", Engine(body).RedactJson(overLimit).FailureCode);
        Assert.Equal("redaction-failed", Engine(body).RedactJson(longKey).FailureCode);
        Assert.True(Engine(body + "disabled: [custom.d]\n").RedactJson(overLimit).Succeeded);
        Assert.True(new PrivacyEngine().RedactJson(overLimit).Succeeded);
    }

    [Fact]
    public void MoreCustomMatchesThanThePerEventLimit_Quarantine()
    {
        PrivacyEngine engine = Engine(Detector(pattern: "a+z|a", tests: "[a]"));
        string atLimit = new('a', CustomPatternDetector.MaximumMatchesPerEvent);
        string half = new('a', CustomPatternDetector.MaximumMatchesPerEvent / 2);

        Assert.True(engine.RedactText(atLimit).Succeeded);
        Assert.Equal("redaction-failed", engine.RedactText(atLimit + "a").FailureCode);
        // The limit is per event, across values (and keys, which are scanned too).
        Assert.True(engine.RedactJson($$"""{"x":"{{half}}","y":"{{half}}"}""").Succeeded);
        Assert.Equal("redaction-failed", engine.RedactJson($$"""{"x":"{{half}}","y":"{{half}}","a":1}""").FailureCode);
    }

    [Fact]
    public void QuadraticPatterns_AreBoundedAndDeterministic()
    {
        PrivacyEngine engine = Engine(Detector(pattern: "a+z|a", tests: "[a]"));
        string json = "{\"a\":\"" + new string('a', 5_000) + "\"}";

        string[] outcomes = [.. Enumerable.Range(0, 50).Select(_ => engine.RedactJson(json).FailureCode ?? "ok")];

        Assert.All(outcomes, outcome => Assert.Equal("redaction-failed", outcome));
    }

    [Fact]
    public void SameEvent_RedactsIdenticallyFiftyTimes()
    {
        // Custom detectors only: built-in detectors keep their own short timeouts.
        PrivacyPolicy policy = Load(Header
            + Detector(id: "custom.token", pattern: "token=.+", tests: "['token=x']")
            + "  - id: custom.word\n    pattern: 'x.+x'\n    wholeWord: true\n    action: sha256\n    tests:\n      match: ['xax']\n").Policy;
        PrivacyEngine engine = new(policy, [.. policy.CustomDetectors.Select(definition => new CustomPatternDetector(definition))]);
        string json = "{\"a\":\"" + string.Concat(Enumerable.Repeat("token=a x\U0001F600x ", 2_000)) + "\"}";

        string?[] results = [.. Enumerable.Range(0, 50).Select(_ => engine.RedactJson(json).RedactedJson)];

        Assert.NotNull(results[0]);
        Assert.All(results, result => Assert.Equal(results[0], result));
    }

    // ------------------------------------------------------------------ A3

    [Theory]
    [InlineData("TKN-[A-Z0-9]+?", "[TKN-A1]", "issued TKN-ABC123 today", "issued TK******23 today")]
    [InlineData("ORD-\\d{4}|ORD-\\d{4}[A-Z]", "[ORD-1234]", "ORD-1234X", "OR*****4X")]
    [InlineData("EMP-\\d", "[EMP-1]", "EMP-1 EMP-2", "EM*-1 EM*-2")]
    [InlineData("-\\d-", "[-1-]", "-1--2-", "********")]
    [InlineData("EMP-\\d{6}", "[EMP-123456]", "XEMP-111111 EMP-222222_ (EMP-333333) EMP-4444445 EMP-555555", "XEMP-111111 EMP-222222_ (EM******33) EMP-4444445 EM******55")]
    public void WholeWord_IsAnAsciiBoundaryOnBothEnds(string pattern, string tests, string input, string expected)
    {
        PrivacyEngine engine = Engine(Detector(pattern: pattern, extra: "    wholeWord: true\n", tests: tests));

        Assert.Equal(expected, engine.RedactText(input).RedactedText);
    }

    [Theory]
    [InlineData("[^a].\\D\\W\\S", "[^a\uFFFE][^\\n\uFFFE][^0-9\uFFFE][^0-9A-Z_a-z\uFFFE][^\\t\\n\\x0B\\f\\r \uFFFE]")]
    [InlineData("[a-z]\\d\\w\\s", "[a-z][0-9][0-9A-Z_a-z][\\t\\n\\x0B\\f\\r ]")]
    public void WholeWord_NegatedClassesExcludeTheSentinel(string pattern, string canonical)
    {
        Assert.Equal(canonical, CustomPatternTranslator.Translate(pattern, ignoreCase: false, wholeWord: true).CanonicalPattern);
        Assert.Equal(
            "[^0-9A-Z_a-z](?:" + canonical + ")[^0-9A-Z_a-z]",
            CustomDetectorDefinition.Create("custom.d", pattern, PrivacyAction.Mask, wholeWord: true).CanonicalPattern);
    }

    [Theory]
    [InlineData("^EMP", 0)]
    [InlineData("EMP$", 3)]
    [InlineData("(a|^b)", 3)]
    public void WholeWord_RejectsAnchors(string pattern, int position)
    {
        Assert.Equal(
            $"Custom detector 'custom.d' pattern has unsupported syntax at position {position}: ^ and $ are not supported with wholeWord.",
            LoadError(Header + Detector(pattern: pattern, extra: "    wholeWord: true\n", tests: "[EMP]")));
    }

    [Fact]
    public void Patterns_RejectTheSentinelCharacter()
    {
        foreach (string pattern in new[] { "a\uFFFE", "[a-\uFFFE]", "\uFFFF" })
        {
            Assert.EndsWith(
                ": characters U+FFFE and U+FFFF are not supported.",
                Assert.Throws<InvalidDataException>(() => CustomDetectorDefinition.Create("custom.d", pattern, PrivacyAction.Mask)).Message,
                StringComparison.Ordinal);
        }
    }

    // ------------------------------------------------------------------ A5

    [Theory]
    [InlineData(0x0000)]
    [InlineData(0x0008)]
    [InlineData(0x000B)]
    [InlineData(0x000C)]
    [InlineData(0x001F)]
    [InlineData(0x007F)]
    [InlineData(0x0085)]
    [InlineData(0x009F)]
    [InlineData(0x2028)]
    [InlineData(0x2029)]
    [InlineData(0xD800)]
    [InlineData(0xDC00)]
    public void Load_RejectsUnsupportedRawCharacters(int codePoint)
    {
        string character = ((char)codePoint).ToString();
        string message = $"Privacy profile contains unsupported character U+{codePoint:X4}.";

        Assert.Equal(message, LoadError(Header + "# comment " + character + "\n"));
        Assert.Equal(message, LoadError(Header + Detector(pattern: "a" + character + "b", tests: "[x]")));
    }

    [Theory]
    [InlineData("\"a\\x0Cb\"", "U+000C")]
    [InlineData("\"a\\Lb\"", "U+2028")]
    [InlineData("\"a\\Nb\"", "U+0085")]
    [InlineData("\"a\\0b\"", "U+0000")]
    [InlineData("\"\\uD83D\\uDE00\"", "U+D83D")]
    [InlineData("\"\\U0000DE00\"", "U+DE00")]
    public void Load_RejectsUnsupportedCharactersFromEscapes(string scalar, string codePoint)
    {
        Assert.Equal(
            $"Privacy profile contains unsupported character {codePoint}.",
            LoadError(Header + "secretFieldNames: [" + scalar + "]\n"));
    }

    [Fact]
    public void Load_AcceptsTabsLineEndingsAndSupplementaryCharacters()
    {
        LoadedPrivacyProfile profile = Load(Header.Replace("\n", "\r\n", StringComparison.Ordinal) + "secretFieldNames: [\"a\\tb\", \"\\U0001F600x\", \"\U0001F600y\"]\r\n# tab\there\n");

        Assert.Equal(["ab", "x", "y"], profile.Policy.SecretFieldNames);
    }

    // ------------------------------------------------------------------ A6

    [Fact]
    public void ProgrammaticCustomDetectorActions_AreHonoured()
    {
        CustomDetectorDefinition remove = CustomDetectorDefinition.Create("custom.d", "secret-\\d+", PrivacyAction.Remove);
        PrivacyPolicy policy = new() { DefaultAction = PrivacyAction.Allow, CustomDetectors = [remove] };

        PrivacyTextResult result = new PrivacyEngine(policy).RedactText("x secret-42 y");

        Assert.Equal("x  y", result.RedactedText);
        Assert.Equal(PrivacyAction.Remove, policy.ResolveAction("custom.d"));
        Assert.True(policy.UsesAction(PrivacyAction.Remove));
    }

    [Fact]
    public void ProgrammaticHmacCustomDetector_NeedsAKey()
    {
        CustomDetectorDefinition hmac = CustomDetectorDefinition.Create("custom.d", "secret-\\d+", PrivacyAction.Hmac);

        Assert.Throws<InvalidOperationException>(() => new PrivacyEngine(new PrivacyPolicy { CustomDetectors = [hmac] }));
        PrivacyEngine keyed = new(new PrivacyPolicy { CustomDetectors = [hmac], HmacKey = Key, HmacKeyId = "k1" });
        Assert.StartsWith("hmac-sha256:k1:", keyed.RedactText("secret-42").RedactedText, StringComparison.Ordinal);
    }

    [Fact]
    public void DetectorActions_OverrideTheDefinitionAction()
    {
        CustomDetectorDefinition remove = CustomDetectorDefinition.Create("custom.d", "secret-\\d+", PrivacyAction.Remove);
        PrivacyPolicy policy = new()
        {
            CustomDetectors = [remove],
            DetectorActions = new Dictionary<string, PrivacyAction>(StringComparer.Ordinal) { ["custom.d"] = PrivacyAction.Replace }
        };

        Assert.Equal("***REDACTED***", new PrivacyEngine(policy).RedactText("secret-42").RedactedText);
        Assert.False(policy.UsesAction(PrivacyAction.Remove));
    }

    [Fact]
    public void YamlAndProgrammaticPolicies_RedactIdentically()
    {
        PrivacyPolicy yaml = Load(Header + "defaultAction: allow\ndetectors: {}\n" + Detector(pattern: "secret-\\d+", action: "remove", tests: "[secret-1]")).Policy;
        PrivacyPolicy programmatic = new()
        {
            DefaultAction = PrivacyAction.Allow,
            DetectorActions = new Dictionary<string, PrivacyAction>(PrivacyPolicy.CreateDefault().DetectorActions, StringComparer.Ordinal),
            CustomDetectors = [CustomDetectorDefinition.Create("custom.d", "secret-\\d+", PrivacyAction.Remove)]
        };
        string json = """{"a":"x secret-42 y alice@example.test 4111111111111111"}""";

        Assert.Equal(new PrivacyEngine(yaml).RedactJson(json).RedactedJson, new PrivacyEngine(programmatic).RedactJson(json).RedactedJson);
    }
}
