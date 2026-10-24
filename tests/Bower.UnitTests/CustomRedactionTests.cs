using System.Text.Json.Nodes;
using Bower.Cli.Commands;
using Bower.Redaction;
using Bower.Redaction.Detectors;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// Custom detectors (custom redaction rules) and secret field names in privacy profiles.
/// The Rust port mirrors these in rust/crates/bower-redaction/tests/custom_redaction.rs and
/// proves byte parity with the generated vectors.
/// </summary>
public sealed class CustomRedactionTests
{
    private const string Header = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n";

    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

    private static string Detector(
        string id = "custom.d",
        string pattern = "x",
        string action = "mask",
        string extra = "",
        string tests = "[x]") =>
        $"customDetectors:\n  - id: {id}\n    pattern: '{pattern}'\n    action: {action}\n{extra}    tests:\n      match: {tests}\n";

    private static LoadedPrivacyProfile Load(string yaml) => PrivacyProfileLoader.Load(yaml, Key, "k1");

    private static string LoadError(string yaml) =>
        Assert.Throws<InvalidDataException>(() => Load(yaml)).Message;

    private static PrivacyEngine Engine(string body) => new(Load(Header + body).Policy);

    private static string ExampleProfile() =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "privacy", "custom-redaction-example.yaml"));

    // ------------------------------------------------------------------ translator

    [Theory]
    [InlineData(@"EMP-\d{6}", false, "EMP-[0-9]{6}")]
    [InlineData(@"EMP-\d{6}", true, "[Ee][Mm][Pp]-[0-9]{6}")]
    [InlineData(@"^\w+$", false, @"\A[0-9A-Z_a-z]+\z")]
    [InlineData(@"\s\S\D\W", false, @"[\t\n\x0B\f\r ][^\t\n\x0B\f\r ][^0-9][^0-9A-Z_a-z]")]
    [InlineData(@"[\d\w\s.-]", false, @"[0-90-9A-Z_a-z\t\n\x0B\f\r .\-]")]
    [InlineData("(a|b)(?:c)x()", false, "(?:a|b)(?:c)x(?:)")]
    [InlineData("a.b", false, @"a[^\n]b")]
    [InlineData(@"x}]\.\#\ \-\/", false, @"x\}\]\.# -/")]
    [InlineData(@"[\]\[\^\\&~]", false, @"[\]\[\^\\\&\~]")]
    [InlineData("a{01}b{2,}c{3,5}?d+?", false, "a{1}b{2,}c{3,5}?d+?")]
    [InlineData("[a-fX]", true, "[a-fA-FXx]")]
    [InlineData("[Z-b]", true, "[Z-bzA-B]")]
    [InlineData("[^q]", true, "[^qQ]")]
    [InlineData("café ſK", true, "[cC][aA][fF]é ſ[Kk]")]
    [InlineData("[\u4E00-\uFFFC]", false, "[\u4E00-\uD7FF\uE000-\uFFFC]")]
    public void Translate_EmitsCanonicalPattern(string pattern, bool ignoreCase, string canonical)
    {
        Assert.Equal(canonical, CustomPatternTranslator.Translate(pattern, ignoreCase).CanonicalPattern);
    }

    [Theory]
    [InlineData("a(?=b)", 1, CustomPatternReasons.Lookaround)]
    [InlineData("(?<!a)b", 0, CustomPatternReasons.Lookaround)]
    [InlineData(@"(a)\1", 3, CustomPatternReasons.BackReference)]
    [InlineData(@"\k<n>", 0, CustomPatternReasons.BackReference)]
    [InlineData(@"\p{L}", 0, CustomPatternReasons.UnicodeProperty)]
    [InlineData("(?i)a", 0, CustomPatternReasons.InlineFlags)]
    [InlineData("(?-i:a)", 0, CustomPatternReasons.InlineFlags)]
    [InlineData("(?<n>a)", 0, CustomPatternReasons.NamedGroup)]
    [InlineData("(?P<n>a)", 0, CustomPatternReasons.NamedGroup)]
    [InlineData("(?>a)", 0, CustomPatternReasons.UnsupportedGroup)]
    [InlineData("(?#c)", 0, CustomPatternReasons.UnsupportedGroup)]
    [InlineData("a(b", 1, CustomPatternReasons.UnbalancedParenthesis)]
    [InlineData("ab)", 2, CustomPatternReasons.UnbalancedParenthesis)]
    [InlineData("x[ab", 1, CustomPatternReasons.UnterminatedClass)]
    [InlineData("[]a]", 0, CustomPatternReasons.EmptyClass)]
    [InlineData("[a[b]]", 2, CustomPatternReasons.NestedClass)]
    [InlineData("[[:alpha:]]", 1, CustomPatternReasons.PosixClass)]
    [InlineData("[a&&b]", 2, CustomPatternReasons.SetOperation)]
    [InlineData("[a-z-[aeiou]]", 4, CustomPatternReasons.SetOperation)]
    [InlineData("[a~~b]", 2, CustomPatternReasons.SetOperation)]
    [InlineData("[z-a]", 1, CustomPatternReasons.InvalidRange)]
    [InlineData(@"[a-\d]", 1, CustomPatternReasons.InvalidRange)]
    [InlineData(@"[\W]", 1, CustomPatternReasons.NegatedShorthandInClass)]
    [InlineData("a{2,1}", 1, CustomPatternReasons.InvalidQuantifier)]
    [InlineData("a{x}", 1, CustomPatternReasons.InvalidQuantifier)]
    [InlineData("a{,2}", 1, CustomPatternReasons.InvalidQuantifier)]
    [InlineData("a{1001}", 1, CustomPatternReasons.QuantifierBound)]
    [InlineData("a{1,99999999999}", 1, CustomPatternReasons.QuantifierBound)]
    [InlineData("*a", 0, CustomPatternReasons.NothingToRepeat)]
    [InlineData("a|+", 2, CustomPatternReasons.NothingToRepeat)]
    [InlineData("^*", 1, CustomPatternReasons.NothingToRepeat)]
    [InlineData("{2}", 0, CustomPatternReasons.NothingToRepeat)]
    [InlineData("a**", 2, CustomPatternReasons.RepeatedQuantifier)]
    [InlineData("a*??", 3, CustomPatternReasons.RepeatedQuantifier)]
    [InlineData("a{2}{3}", 4, CustomPatternReasons.RepeatedQuantifier)]
    [InlineData(@"\bx", 0, CustomPatternReasons.WordBoundary)]
    [InlineData(@"x\>", 1, CustomPatternReasons.WordBoundary)]
    [InlineData(@"\Ax", 0, CustomPatternReasons.AnchorEscape)]
    [InlineData(@"x\Z", 1, CustomPatternReasons.AnchorEscape)]
    [InlineData(@"\x41", 0, CustomPatternReasons.UnsupportedEscape)]
    [InlineData(@"\u0041", 0, CustomPatternReasons.UnsupportedEscape)]
    [InlineData(@"\0", 0, CustomPatternReasons.UnsupportedEscape)]
    [InlineData(@"\é", 0, CustomPatternReasons.UnsupportedEscape)]
    [InlineData("ab\\", 2, CustomPatternReasons.TrailingBackslash)]
    [InlineData("a\U0001F600", 1, CustomPatternReasons.SupplementaryCharacter)]
    [InlineData("[a-\uFFFF]", 3, CustomPatternReasons.ReservedCharacter)]
    public void Translate_RejectsUnsupportedSyntaxWithPosition(string pattern, int position, string reason)
    {
        CustomPatternSyntaxException exception = Assert.Throws<CustomPatternSyntaxException>(
            () => CustomPatternTranslator.Translate(pattern, ignoreCase: false));

        Assert.Equal(position, exception.Position);
        Assert.Equal(reason, exception.Reason);
        Assert.Contains(reason, CustomPatternReasons.All);
    }

    [Theory]
    [InlineData("EMP-\\d{6}", 10, false)]
    [InlineData("(a{64}){8}", 512, false)]
    [InlineData("(a{64}){9}", 513, false)]
    [InlineData("((((a{1000}){1000}){1000}){1000})", 513, false)]
    [InlineData("a|b|c", 3, false)]
    [InlineData("a*", 1, true)]
    [InlineData("x(a|)", 2, false)]
    [InlineData("(a|)", 1, true)]
    [InlineData("^$", 2, true)]
    [InlineData("a{0}", 1, true)]
    public void Translate_EstimatesComplexityAndEmptyMatches(string pattern, int complexity, bool matchesEmpty)
    {
        CustomPatternTranslation translation = CustomPatternTranslator.Translate(pattern, ignoreCase: false);

        Assert.Equal(complexity, translation.Complexity);
        Assert.Equal(matchesEmpty, translation.MatchesEmpty);
    }

    [Fact]
    public void Reasons_AreDistinct()
    {
        Assert.Equal(CustomPatternReasons.All.Count, CustomPatternReasons.All.Distinct(StringComparer.Ordinal).Count());
    }

    // ------------------------------------------------------------------ definitions

    [Theory]
    [InlineData("custom.employee-id", true)]
    [InlineData("custom.a1-b2-c3", true)]
    [InlineData("custom.", false)]
    [InlineData("custom", false)]
    [InlineData("Custom.x", false)]
    [InlineData("custom.A", false)]
    [InlineData("custom.a--b", false)]
    [InlineData("custom.-a", false)]
    [InlineData("custom.a-", false)]
    [InlineData("custom.a_b", false)]
    [InlineData("custom.a.b", false)]
    [InlineData("au.tfn", false)]
    [InlineData(null, false)]
    public void IsValidId_FollowsTheCustomNameRule(string? id, bool valid)
    {
        Assert.Equal(valid, CustomDetectorDefinition.IsValidId(id));
    }

    [Fact]
    public void IsValidId_AllowsAtMost64Characters()
    {
        Assert.True(CustomDetectorDefinition.IsValidId("custom." + new string('a', 57)));
        Assert.False(CustomDetectorDefinition.IsValidId("custom." + new string('a', 58)));
    }

    [Fact]
    public void Create_ValidatesLikeTheLoader()
    {
        CustomDetectorDefinition definition = CustomDetectorDefinition.Create(
            "custom.d", "emp-\\d{6}", PrivacyAction.Hmac, ignoreCase: true, wholeWord: true, description: "d");

        Assert.Equal(@"[^0-9A-Z_a-z](?:[eE][mM][pP]-[0-9]{6})[^0-9A-Z_a-z]", definition.CanonicalPattern);
        Assert.Equal("emp-\\d{6}", definition.Pattern);
        Assert.Equal(
            "Custom detector 'custom.d' cannot use action allow; use alert-only to record matches without redacting.",
            Assert.Throws<InvalidDataException>(() => CustomDetectorDefinition.Create("custom.d", "x", PrivacyAction.Allow)).Message);
        Assert.True(definition.WholeWord);
        Assert.Equal(PrivacyAction.Hmac, definition.Action);
        Assert.Equal(
            "Custom detector 'custom.d' pattern must not match an empty string.",
            Assert.Throws<InvalidDataException>(() => CustomDetectorDefinition.Create("custom.d", "a?", PrivacyAction.Mask)).Message);
        Assert.Equal(
            "Custom detector 'custom.d' pattern is too complex.",
            Assert.Throws<InvalidDataException>(() => CustomDetectorDefinition.Create("custom.d", "(a{100}){11}", PrivacyAction.Mask)).Message);
        Assert.StartsWith(
            "Custom detector id 'bad'",
            Assert.Throws<InvalidDataException>(() => CustomDetectorDefinition.Create("bad", "x", PrivacyAction.Mask)).Message,
            StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ loader errors

    public static TheoryData<string, string> LoaderErrors()
    {
        string valid = "  - id: {0}\n    pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n";
        return new TheoryData<string, string>
        {
            {
                Header + "customDetectors:\n" + string.Concat(Enumerable.Range(0, 33).Select(i => string.Format(System.Globalization.CultureInfo.InvariantCulture, valid, $"custom.d{i}"))),
                "Privacy profile may define at most 32 custom detectors."
            },
            { Header + "customDetectors: ~\n", "Privacy profile 'customDetectors' must not be null." },
            { Header + "customDetectors:\n  - ~\n", "Privacy profile custom detector must not be null." },
            {
                Header + Detector(id: "custom.Bad"),
                "Custom detector id 'custom.Bad' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters)."
            },
            {
                Header + "customDetectors:\n  - pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n",
                "Custom detector id '' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters)."
            },
            {
                Header + "customDetectors:\n" + string.Format(System.Globalization.CultureInfo.InvariantCulture, valid, "custom.a") + string.Format(System.Globalization.CultureInfo.InvariantCulture, valid, "custom.a"),
                "Custom detector id 'custom.a' is defined more than once."
            },
            {
                Header + Detector(extra: "    description: " + new string('d', 257) + "\n"),
                "Custom detector 'custom.d' description must be at most 256 characters."
            },
            { Header + Detector(pattern: ""), "Custom detector 'custom.d' pattern must be 1-512 characters." },
            { Header + Detector(pattern: new string('x', 513)), "Custom detector 'custom.d' pattern must be 1-512 characters." },
            {
                Header + "customDetectors:\n  - id: custom.d\n    action: mask\n    tests:\n      match: [x]\n",
                "Custom detector 'custom.d' pattern must be 1-512 characters."
            },
            {
                Header + Detector(pattern: "x(?<=y)"),
                "Custom detector 'custom.d' pattern has unsupported syntax at position 1: lookaround is not supported."
            },
            { Header + Detector(pattern: "(x{100}){11}"), "Custom detector 'custom.d' pattern is too complex." },
            { Header + Detector(pattern: "x*"), "Custom detector 'custom.d' pattern must not match an empty string." },
            {
                Header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    tests:\n      match: [x]\n",
                "Custom detector 'custom.d' requires an action."
            },
            { Header + Detector(action: "~"), "Custom detector 'custom.d' requires an action." },
            { Header + Detector(action: "obliterate"), "Unknown privacy action 'obliterate'." },
            {
                Header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n",
                "Custom detector 'custom.d' requires at least one tests.match sample."
            },
            { Header + Detector(tests: "[]"), "Custom detector 'custom.d' requires at least one tests.match sample." },
            { Header + Detector(tests: "~"), "Custom detector 'custom.d' requires at least one tests.match sample." },
            {
                Header + Detector(tests: "[" + string.Join(", ", Enumerable.Repeat("x", 17)) + "]"),
                "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters."
            },
            {
                Header + Detector(tests: "[x]\n      noMatch: [" + string.Join(", ", Enumerable.Repeat("y", 17)) + "]"),
                "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters."
            },
            {
                Header + Detector(tests: "[x, '']"),
                "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters."
            },
            {
                Header + Detector(tests: "[" + new string('x', 1025) + "]"),
                "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters."
            },
            {
                Header + Detector(tests: "[x]\n      noMatch: ~"),
                "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters."
            },
            { Header + Detector(tests: "[x, y]"), "Custom detector 'custom.d' did not match tests.match[1]." },
            { Header + Detector(tests: "[x]\n      noMatch: [y, axb]"), "Custom detector 'custom.d' matched tests.noMatch[1]." },
            {
                Header + Detector() + "detectors:\n  custom.d: remove\n",
                "Custom detector 'custom.d' sets its action in customDetectors, not detectors."
            },
            { Header + Detector() + "detectors:\n  custom.other: remove\n", "Unknown detector id 'custom.other'." },
            { Header + Detector() + "disabled: [custom.other]\n", "Unknown detector id 'custom.other'." },
            { Header + Detector() + "enableOptIn: [custom.d]\n", "Unknown detector id 'custom.d'." },
            { Header + "secretFieldNames: ~\n", "Privacy profile 'secretFieldNames' must not be null." },
            {
                Header + "secretFieldNames: [" + string.Join(", ", Enumerable.Range(0, 65).Select(i => $"n{i}")) + "]\n",
                "Privacy profile may list at most 64 secretFieldNames of 1-128 characters."
            },
            { Header + "secretFieldNames: [ok, '']\n", "Privacy profile may list at most 64 secretFieldNames of 1-128 characters." },
            { Header + "secretFieldNames: [ok, ~]\n", "Privacy profile may list at most 64 secretFieldNames of 1-128 characters." },
            {
                Header + "secretFieldNames: [" + new string('a', 129) + "]\n",
                "Privacy profile may list at most 64 secretFieldNames of 1-128 characters."
            },
            { Header + "secretFieldNames: [ok, '---']\n", "Secret field name '---' has no letters or digits." }
        };
    }

    [Theory]
    [MemberData(nameof(LoaderErrors))]
    public void Load_RejectsInvalidCustomDetectorsAndSecretFieldNames(string yaml, string message)
    {
        Assert.Equal(message, LoadError(yaml));
    }

    [Theory]
    [InlineData("    unknownKey: 1\n")]
    [InlineData("    ignoreCase: maybe\n")]
    public void Load_RejectsUnknownKeysAndBadScalarsAsYamlErrors(string extra)
    {
        Assert.StartsWith("Privacy profile is invalid at line", LoadError(Header + Detector(extra: extra)), StringComparison.Ordinal);
    }

    [Fact]
    public void Load_HmacCustomActionNeedsAKey()
    {
        Assert.Throws<InvalidOperationException>(() => PrivacyProfileLoader.Load(Header + Detector(action: "hmac")));
        Assert.Equal(PrivacyAction.Hmac, Load(Header + Detector(action: "hmac")).Policy.ResolveAction("custom.d"));
    }

    [Fact]
    public void Load_AcceptsLimitsExactly()
    {
        string valid = "  - id: {0}\n    pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n";
        string yaml = Header + "customDetectors:\n"
            + string.Concat(Enumerable.Range(0, 32).Select(i => string.Format(System.Globalization.CultureInfo.InvariantCulture, valid, $"custom.d{i}")))
            + "secretFieldNames: [" + string.Join(", ", Enumerable.Range(0, 64).Select(i => $"n{i}")) + "]\n";

        LoadedPrivacyProfile profile = Load(yaml);

        Assert.Equal(32, profile.Policy.CustomDetectors.Count);
        Assert.Equal(64, profile.Policy.SecretFieldNames.Count);
        Assert.Equal(32, profile.CustomDetectorTests);
        _ = Load(Header + Detector(pattern: new string('x', 512), tests: "[" + new string('x', 512) + "]"));
        _ = Load(Header + Detector(tests: "[" + new string('x', 1024) + "]"));
        _ = Load(Header + Detector(extra: "    description: " + new string('d', 256) + "\n"));
    }

    // ------------------------------------------------------------------ loaded policy

    [Fact]
    public void Load_PutsDefinitionsAndNormalisedNamesOnThePolicy()
    {
        LoadedPrivacyProfile profile = Load(Header
            + "customDetectors:\n"
            + "  - id: custom.ref\n    description: refs\n    pattern: 'ref-\\d+'\n    ignoreCase: yes\n    wholeWord: on\n    action: Alert-Only\n"
            + "    tests:\n      match: [REF-1, 'x ref-22 y']\n      noMatch: [xref-1]\n"
            + "secretFieldNames: [sessionKey, SESSION_KEY, Session-Key, 'Пароль', ÜberSecret, a1]\n"
            + "disabled: [custom.ref]\n");
        PrivacyPolicy policy = profile.Policy;
        CustomDetectorDefinition definition = Assert.Single(policy.CustomDetectors);

        Assert.Equal("custom.ref", definition.Id);
        Assert.Equal("refs", definition.Description);
        Assert.Equal(@"[^0-9A-Z_a-z](?:[rR][eE][fF]-[0-9]+)[^0-9A-Z_a-z]", definition.CanonicalPattern);
        Assert.True(definition.IgnoreCase);
        Assert.True(definition.WholeWord);
        Assert.Equal(PrivacyAction.AlertOnly, definition.Action);
        Assert.Equal(PrivacyAction.AlertOnly, policy.ResolveAction("custom.ref"));
        Assert.False(policy.IsDetectorEnabled("custom.ref"));
        Assert.Equal(["sessionkey", "пароль", "übersecret", "a1"], policy.SecretFieldNames);
        Assert.Equal(3, profile.CustomDetectorTests);
    }

    [Fact]
    public void Load_HashCoversTheNewSections()
    {
        string a = Load(Header + Detector()).Hash;
        string b = Load(Header + Detector(extra: "    wholeWord: false\n")).Hash;
        string c = Load(Header + "secretFieldNames: [a]\n").Hash;

        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public void Validate_RejectsNullCollections()
    {
        Assert.Throws<ArgumentException>(() => new PrivacyPolicy { CustomDetectors = null! }.Validate());
        Assert.Throws<ArgumentException>(() => new PrivacyPolicy { SecretFieldNames = [null!] }.Validate());
    }

    // ------------------------------------------------------------------ engine

    [Fact]
    public void ExampleProfile_LoadsAndRedactsTheSample()
    {
        LoadedPrivacyProfile profile = Load(ExampleProfile());
        JsonEventRedactor redactor = new(profile.Policy);

        Bower.Abstractions.RedactionResult result = redactor.Redact(
            """{"actor":{"username":"alice"},"msg":"EMP-123456 opened CUST-ab1234 see INC0012345, not XEMP-000001","sessionKey":"s","webhook_nonce":"n"}""");
        JsonNode node = JsonNode.Parse(result.RedactedJson!)!;

        Assert.True(result.Succeeded);
        Assert.Equal("contoso-custom-redaction", profile.Id);
        Assert.Equal(3, profile.Policy.CustomDetectors.Count);
        Assert.Equal(13, profile.CustomDetectorTests);
        string message = node["msg"]!.GetValue<string>();
        Assert.StartsWith("EM******56 opened hmac-sha256:k1:", message, StringComparison.Ordinal);
        Assert.EndsWith(" see ***REDACTED***, not XEMP-000001", message, StringComparison.Ordinal);
        Assert.Null(node["sessionKey"]);
        Assert.Null(node["webhook_nonce"]);
        Assert.StartsWith("hmac-sha256:k1:", node["actor"]!["username"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Contains("custom.employee-id", result.PrivacyDetected!);
        Assert.Equal("HMAC", result.PrivacyActions!["custom.customer-ref"]);
    }

    [Fact]
    public void WholeWord_SkipsAdjacentMatchesAndKeepsScanning()
    {
        PrivacyEngine engine = Engine(Detector(pattern: @"EMP-\d{6}", extra: "    wholeWord: true\n", tests: "[EMP-123456]"));

        PrivacyTextResult result = engine.RedactText("XEMP-111111 EMP-222222_ (EMP-333333) EMP-4444445 EMP-555555");

        Assert.Equal("XEMP-111111 EMP-222222_ (EM******33) EMP-4444445 EM******55", result.RedactedText);
        Assert.All(result.Findings, finding => Assert.Equal(DetectorCategories.Custom, finding.Category));
    }

    [Fact]
    public void WholeWord_ResumesAfterASkippedMatch()
    {
        // The first match "aab" is preceded by a word character; scanning resumes after
        // it, exactly like the engine's normal next-match iteration.
        PrivacyEngine engine = Engine(Detector(pattern: "a+b", extra: "    wholeWord: true\n", tests: "[ab]"));

        Assert.Equal("xaab ****", engine.RedactText("xaab aaab").RedactedText);
    }

    [Fact]
    public void CustomDetectors_JoinLongestFirstOverlapResolution()
    {
        PrivacyEngine engine = Engine(
            "customDetectors:\n"
            + "  - id: custom.mail\n    pattern: '[a-z]+@example\\.test'\n    action: remove\n    tests:\n      match: [a@example.test]\n"
            + "  - id: custom.long\n    pattern: 'card \\d{16}'\n    action: replace\n    tests:\n      match: [card 4111111111111111]\n");

        PrivacyTextResult result = engine.RedactText("alice@example.test card 4111111111111111");

        // Equal spans keep the built-in (earlier in the catalogue); longer custom spans win.
        Assert.Equal("a***@example.test ***REDACTED***", result.RedactedText);
        Assert.Equal(["custom.long", "id.email"], result.Findings.Select(finding => finding.DetectorId).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CustomDetectors_ScanPropertyNamesNumbersAndArrays()
    {
        PrivacyEngine engine = Engine(Detector(pattern: @"\d{12}", action: "sha256", tests: "['123456789012']"));

        PrivacyScanResult result = engine.RedactJson("""{"123456789012":"k","n":123456789012,"list":["x 123456789012"]}""");
        JsonObject node = JsonNode.Parse(result.RedactedJson!)!.AsObject();

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("123456789012", result.RedactedJson!, StringComparison.Ordinal);
        Assert.StartsWith("sha256:", node["n"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Contains(result.Findings, finding => finding.Path == "$.[key]");
    }

    [Fact]
    public void CustomDetectors_WidenMatchesToWholeSurrogatePairs()
    {
        PrivacyEngine engine = Engine(
            "customDetectors:\n"
            + "  - id: custom.one\n    pattern: 'P[^a]Q'\n    action: remove\n    tests:\n      match: [PxQ]\n"
            + "  - id: custom.two\n    pattern: 'R[^a][^a]S'\n    action: remove\n    tests:\n      match: [RxyS]\n"
            + "  - id: custom.dot\n    pattern: 'x.'\n    action: remove\n    tests:\n      match: [xy]\n");

        // .NET sees two UTF-16 units per emoji: "x" plus the high surrogate is widened to
        // the whole emoji instead of being dropped.
        Assert.Equal("P\U0001F600Q   ", engine.RedactText("P\U0001F600Q R\U0001F600S x\U0001F600 xy").RedactedText);
    }

    [Fact]
    public void CustomDetectors_WidenMatchesStartingInsideAPair()
    {
        // The first candidate is the emoji's low surrogate plus "b": widened to the emoji.
        PrivacyEngine engine = Engine(Detector(pattern: "[^a]b", action: "remove", tests: "[xb]"));

        Assert.Equal("  ", engine.RedactText("\U0001F600b éb xb").RedactedText);
    }

    [Fact]
    public void CustomDetectors_RedactThroughASplitEmoji()
    {
        PrivacyEngine engine = Engine(Detector(pattern: "key=.{8}", action: "replace", tests: "[key=12345678]"));

        Assert.Equal("***REDACTED*** rest", engine.RedactText("key=s3cr3tk\U0001F600 rest").RedactedText);
    }

    [Fact]
    public void SecretFieldNames_AreHandledLikeFieldNameSecrets()
    {
        PrivacyEngine engine = Engine("secretFieldNames: [sessionKey, 'Пароль']\n");

        PrivacyScanResult result = engine.RedactJson("""{"SESSION_KEY":"s","session-key":"s","ПАРОЛЬ":"s","sessionKeys":"kept"}""");
        JsonObject node = JsonNode.Parse(result.RedactedJson!)!.AsObject();

        Assert.Equal(["sessionKeys", "privacy"], node.Select(property => property.Key));
        Assert.All(result.Findings, finding => Assert.Equal(DetectorIds.FieldNameSecret, finding.DetectorId));
        Assert.Equal(3, result.Findings.Count);
    }

    [Fact]
    public void SecretFieldNames_FollowTheFieldNameSecretActionAndSwitch()
    {
        string names = "secretFieldNames: [sessionKey]\n";
        string json = """{"sessionKey":"s"}""";

        PrivacyScanResult alert = Engine(names + "detectors:\n  field-name-secret: alert-only\n").RedactJson(json);
        PrivacyScanResult disabled = Engine(names + "disabled: [field-name-secret]\n").RedactJson(json);

        Assert.Equal("s", JsonNode.Parse(alert.RedactedJson!)!["sessionKey"]!.GetValue<string>());
        Assert.Equal(PrivacyAction.AlertOnly, Assert.Single(alert.Findings).Action);
        Assert.Equal(json, disabled.RedactedJson);
    }

    [Fact]
    public void CompositeFieldNameDetector_KeepsTheInnerIdentity()
    {
        CompositeFieldNameDetector detector = new(new FieldNameSecretDetector(), ["sessionkey"]);

        Assert.Equal(DetectorIds.FieldNameSecret, detector.Id);
        Assert.True(detector.MatchesFieldName("sessionkey"));
        Assert.True(detector.MatchesFieldName("password"));
        Assert.False(detector.MatchesFieldName("sessionkeys"));
        Assert.False(detector.MatchesFieldName(string.Empty));
    }

    [Fact]
    public void CustomDetectors_DoNotRaiseSensitiveDataEvents()
    {
        Assert.False(PrivacyEngine.IsSecurityEventWorthy("custom.employee-id"));
    }

    [Fact]
    public void ExplicitDetectorLists_AreUsedAsGiven()
    {
        PrivacyPolicy policy = Load(Header + Detector(pattern: "secret-x", tests: "[secret-x]")).Policy;

        Assert.Contains(new PrivacyEngine(policy).Detectors, detector => detector.Id == "custom.d");
        Assert.DoesNotContain(new PrivacyEngine(policy, DetectorCatalog.CreateDefaultValueDetectors()).Detectors, detector => detector.Id == "custom.d");
    }

    [Fact]
    public void FieldNameNormalizer_LowersLettersAndDropsTheRest()
    {
        Assert.Equal("xcontososignature", FieldNameNormalizer.Normalize("x-Contoso_Signature"));
        Assert.Equal("пароль", FieldNameNormalizer.Normalize("ПАРОЛЬ"));
        Assert.Equal("password", FieldNameNormalizer.Normalize("pass\U0001F600word"));
    }

    // ------------------------------------------------------------------ adversarial

    [Fact]
    public void CatastrophicBacktrackingShapes_RunInLinearTime()
    {
        PrivacyEngine engine = Engine(Detector(pattern: "(a+)+b", tests: "[ab]"));

        PrivacyTextResult result = engine.RedactText(new string('a', 60_000) + "!");

        Assert.True(result.Succeeded);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void RedactionFailure_StillQuarantinesWithCustomDetectors()
    {
        PrivacyPolicy policy = Load(Header + Detector(pattern: @"EMP-\d{6}", tests: "[EMP-123456]") + "secretFieldNames: [sessionKey]\n").Policy;
        PrivacyEngine failing = new(policy, [.. DetectorCatalog.CreateValueDetectors(policy), new ThrowingDetector()]);
        PrivacyEngine engine = new(policy);

        PrivacyScanResult thrown = failing.RedactJson("""{"a":"EMP-123456"}""");
        PrivacyScanResult duplicate = engine.RedactJson("""{"a":"EMP-123456","a":"x"}""");
        PrivacyTextResult text = failing.RedactText("EMP-123456");

        Assert.Equal(("redaction-failed", (string?)null), (thrown.FailureCode, thrown.RedactedJson));
        Assert.Equal(("redaction-failed", (string?)null), (duplicate.FailureCode, duplicate.RedactedJson));
        Assert.Equal(("redaction-failed", (string?)null), (text.FailureCode, text.RedactedText));
    }

    [Fact]
    public void LongSingleMatches_StayBoundedAndSucceed()
    {
        // Nested unbounded loops inside a counted repetition stay linear; .NET may spend
        // seconds on a 1 MB single match but must still redact (never a partial result).
        // Only the custom detector: built-in detectors keep their own short timeouts.
        PrivacyPolicy policy = Load(Header + Detector(pattern: "(?:.+){8}", tests: "[xxxxxxxx]")).Policy;
        PrivacyEngine engine = new(policy, [new CustomPatternDetector(policy.CustomDetectors[0])]);

        PrivacyScanResult result = engine.RedactJson("{\"a\":\"" + new string('x', 60_000) + "\"}");

        Assert.True(result.Succeeded);
        Assert.StartsWith("xx***", JsonNode.Parse(result.RedactedJson!)!["a"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Contains(result.Findings, finding => finding.DetectorId == "custom.d");
    }

    private sealed class ThrowingDetector : ISensitiveDetector
    {
        public string Id => "custom.throwing";

        public string Category => DetectorCategories.Custom;

        public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches) =>
            throw new InvalidOperationException("detector failure");
    }

    [Fact]
    public void AttackerControlledValues_CannotEscapeAnchorsOrNewlines()
    {
        PrivacyEngine engine = Engine(Detector(pattern: "^secret$", tests: "[secret]"));

        Assert.Equal("secret\n", engine.RedactText("secret\n").RedactedText);
        Assert.Equal("se**et", engine.RedactText("secret").RedactedText);
        Assert.Equal("x secret", engine.RedactText("x secret").RedactedText);
    }

    // ------------------------------------------------------------------ packs

    [Fact]
    public void PackPrivacyProfiles_CarryCustomDetectors()
    {
        PrivacyPolicy policy = Bower.Packs.PackArchive.TestPrivacyPolicy(ExampleProfile());

        Assert.Equal(3, policy.CustomDetectors.Count);
        Assert.Equal(
            "Custom detector 'custom.d' did not match tests.match[0].",
            Assert.Throws<InvalidDataException>(() => Bower.Packs.PackArchive.TestPrivacyPolicy(Header + Detector(tests: "[y]"))).Message);
    }

    // ------------------------------------------------------------------ CLI

    [Fact]
    public void CliValidate_DescribesMetadataOnly()
    {
        PrivacyValidationOutput output = PrivacyCommands.Describe(
            ExampleProfile(), Key, null, """{"msg":"EMP-123456","sessionKey":"s"}""");

        Assert.True(output.Valid);
        Assert.Equal("contoso-custom-redaction", output.ProfileId);
        Assert.Equal(
            ["custom.employee-id:Mask", "custom.customer-ref:Hmac", "custom.internal-ticket:Replace"],
            output.CustomDetectors.Select(detector => $"{detector.Id}:{detector.Action}"));
        Assert.Equal(3, output.SecretFieldNames);
        Assert.Equal(13, output.TestsPassed);
        Assert.True(output.Sample!.Succeeded);
        Assert.DoesNotContain("EMP-123456", output.Sample.Redacted!, StringComparison.Ordinal);
        Assert.Null(PrivacyCommands.Describe(ExampleProfile(), Key, null, null).Sample);
        Assert.Throws<InvalidDataException>(() => PrivacyCommands.Describe(Header + Detector(tests: "[y]"), Key, null, null));
    }
}
