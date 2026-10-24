using System.Globalization;
using Bower.PolicyEngine;

namespace Bower.UnitTests;

public sealed class PolicyLoaderTests
{
    [Fact]
    public void LoadFile_ParsesAndHashesVersionedYamlDeterministically()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "policy.yaml");
        File.WriteAllText(
            path,
            """
            apiVersion: bower.security/v1
            kind: TelemetryPolicy
            metadata:
              id: BWR-POL-TEST
              name: Test policy
              version: 1.0.0
              owner: Test
            match:
              eventTypes:
                - authentication_failure
            requirements:
              requiredFields:
                - eventType
            decision:
              action: accept
              minimumValueScore: 1
              neverSample: true
            """);

        LoadedPolicy first = PolicyLoader.LoadFile(path);
        LoadedPolicy second = PolicyLoader.LoadFile(path);

        Assert.Equal("BWR-POL-TEST", first.Policy.Metadata.Id);
        Assert.Equal(first.Hash, second.Hash);
        Assert.StartsWith("sha256:", first.Hash, StringComparison.Ordinal);
    }

    [Fact]
    public void LoadDirectory_AcceptsShippedDefaultPolicies()
    {
        IReadOnlyList<LoadedPolicy> policies = PolicyLoader.LoadDirectory(
            Path.Combine(AppContext.BaseDirectory, "policies", "default"));

        Assert.Equal(5, policies.Count);
    }

    [Fact]
    public void LoadFile_RejectsMisspeltKey()
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(directory, ValidPolicy.Replace("requirements:", "requirments:", StringComparison.Ordinal));

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
        Assert.Contains("policy.yaml", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoadFile_RejectsCategoryOnlyMatch()
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(
            directory,
            ValidPolicy.Replace(
                "  eventTypes:\n    - authentication_failure",
                "  eventCategories:\n    - authentication",
                StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("-1")]
    [InlineData("acept")]
    public void LoadFile_RejectsNumericOrUnknownActions(string action)
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(
            directory,
            ValidPolicy.Replace("action: accept", $"action: \"{action}\"", StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
    }

    [Theory]
    [InlineData("en-AU")]
    [InlineData("en-US")]
    [InlineData("de-DE")]
    [InlineData("ja-JP")]
    public void LoadFile_ParsesIsoReviewDateIdenticallyInEveryCulture(string culture)
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(
            directory,
            ValidPolicy.Replace("  owner: Test\n", "  owner: Test\n  reviewDate: 2027-01-02\n", StringComparison.Ordinal));
        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
            string invariantHash = PolicyLoader.LoadFile(path).Hash;
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            LoadedPolicy loaded = PolicyLoader.LoadFile(path);

            Assert.Equal(new DateOnly(2027, 1, 2), loaded.Policy.Metadata.ReviewDate);
            Assert.Equal(invariantHash, loaded.Hash);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Theory]
    [InlineData("'01/02/2027'")]
    [InlineData("2027/01/02")]
    [InlineData("2027-1-2")]
    [InlineData("27-1-2")]
    [InlineData("Jan 2, 2027")]
    [InlineData("2027-01-02T00:00:00Z")]
    [InlineData("2027-02-30")]
    [InlineData("0000-01-01")]
    [InlineData("\" 2027-01-02\"")]
    [InlineData("{a: b}")]
    [InlineData("[2027-01-02]")]
    public void LoadFile_RejectsNonIsoReviewDate(string value)
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(
            directory,
            ValidPolicy.Replace("  owner: Test\n", $"  owner: Test\n  reviewDate: {value}\n", StringComparison.Ordinal));

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
        Assert.Equal(
            "Policy 'policy.yaml' is invalid at line 8: Expected an ISO 8601 date (yyyy-MM-dd).",
            error.Message);
    }

    [Theory]
    [InlineData("metadata:\n  id: BWR-POL-TEST\n  name: Test policy\n  version: 1.0.0\n  owner: Test\n", "", "Policy metadata id and version are required.")]
    [InlineData("metadata:\n  id: BWR-POL-TEST\n  name: Test policy\n  version: 1.0.0\n  owner: Test\n", "metadata: ~\n", "Policy metadata id and version are required.")]
    [InlineData("match:\n  eventTypes:\n    - authentication_failure\n", "", "Policy match must list at least one eventType.")]
    [InlineData("  eventTypes:\n    - authentication_failure\n", "  eventTypes: ~\n", "Policy match must list at least one eventType.")]
    [InlineData("decision:\n  action: accept\n  minimumValueScore: 1\n  neverSample: true", "", "Policy decision section is required.")]
    [InlineData("decision:\n  action: accept\n  minimumValueScore: 1\n  neverSample: true", "decision: ~", "Policy decision section is required.")]
    [InlineData("    - authentication_failure\n", "    - authentication_failure\n  eventCategories: ~\n", "Policy match eventCategories must be a list of non-blank values.")]
    [InlineData("    - authentication_failure\n", "    - authentication_failure\n  eventCategories: [authentication, ~]\n", "Policy match eventCategories must be a list of non-blank values.")]
    [InlineData("    - authentication_failure\n", "    - authentication_failure\n  eventCategories: [' ']\n", "Policy match eventCategories must be a list of non-blank values.")]
    [InlineData("requirements:\n  requiredFields:\n    - eventType\n", "", "Policy requirements section is required.")]
    [InlineData("requirements:\n  requiredFields:\n    - eventType\n", "requirements: ~\n", "Policy requirements section is required.")]
    [InlineData("  requiredFields:\n    - eventType\n", "  requiredFields: ~\n", "Policy requirements requiredFields must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - eventType\n    - ~\n", "Policy requirements requiredFields must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - ''\n", "Policy requirements requiredFields must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - eventType\n  atLeastOne: ~\n", "Policy requirements atLeastOne must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - eventType\n  atLeastOne: [actor.userId, '  ']\n", "Policy requirements atLeastOne must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - eventType\n  recommendedFields: ~\n", "Policy requirements recommendedFields must be a list of non-blank field paths.")]
    [InlineData("    - eventType\n", "    - eventType\n  recommendedFields: [~]\n", "Policy requirements recommendedFields must be a list of non-blank field paths.")]
    public void LoadFile_RejectsNullSectionsListsAndFieldPaths(string original, string replacement, string message)
    {
        using TemporaryDirectory directory = new();
        Assert.Contains(original, ValidPolicy, StringComparison.Ordinal);
        string path = WritePolicy(directory, ValidPolicy.Replace(original, replacement, StringComparison.Ordinal));

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
        Assert.Equal(message, error.Message);
    }

    [Theory]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 070", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 0x10", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 0b11", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: +5", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 1_0", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 1:30", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: \" 7 \"", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 70.0", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: 2147483648", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: {a: 1}", 16, "Expected a decimal integer such as 70.")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: [1]", 16, "Expected a decimal integer such as 70.")]
    [InlineData("neverSample: true", "neverSample: yes", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: on", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: y", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: off", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: True", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: 1", 17, "Expected true or false.")]
    [InlineData("neverSample: true", "neverSample: {a: 1}", 17, "Expected true or false.")]
    public void LoadFile_RejectsNonCanonicalScalars(string original, string replacement, int line, string message)
    {
        using TemporaryDirectory directory = new();
        string path = WritePolicy(directory, ValidPolicy.Replace(original, replacement, StringComparison.Ordinal));

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadFile(path));
        Assert.Equal($"Policy 'policy.yaml' is invalid at line {line}: {message}", error.Message);
    }

    [Theory]
    [InlineData("minimumValueScore: 1", "minimumValueScore: \"1\"")]
    [InlineData("minimumValueScore: 1", "minimumValueScore: !!str 1")]
    [InlineData("neverSample: true", "neverSample: \"true\"")]
    public void LoadFile_AcceptsCanonicalScalarsInAnyStyleWithUnchangedHash(string original, string replacement)
    {
        using TemporaryDirectory directory = new();
        string canonical = PolicyLoader.LoadFile(WritePolicy(directory, ValidPolicy)).Hash;

        LoadedPolicy loaded = PolicyLoader.LoadFile(
            WritePolicy(directory, ValidPolicy.Replace(original, replacement, StringComparison.Ordinal)));

        Assert.Equal(ValidPolicyHash, canonical);
        Assert.Equal(canonical, loaded.Hash);
    }

    [Fact]
    public void LoadFile_KeepsDefaultsForPlainNullValueTypes()
    {
        using TemporaryDirectory directory = new();
        LoadedPolicy loaded = PolicyLoader.LoadFile(WritePolicy(
            directory,
            ValidPolicy
                .Replace("minimumValueScore: 1", "minimumValueScore: ~", StringComparison.Ordinal)
                .Replace("neverSample: true", "neverSample: null", StringComparison.Ordinal)
                .Replace("  owner: Test\n", "  owner: Test\n  reviewDate:\n", StringComparison.Ordinal)));

        Assert.Equal(0, loaded.Policy.Decision.MinimumValueScore);
        Assert.False(loaded.Policy.Decision.NeverSample);
        Assert.Null(loaded.Policy.Metadata.ReviewDate);
    }

    [Fact]
    public void Evaluator_DeniesUnknownTypeEvenForCategoryOnlyPolicy()
    {
        LoadedPolicy categoryOnly = TestEvents.AuthenticationPolicy() with
        {
            Policy = TestEvents.AuthenticationPolicy().Policy with
            {
                Match = new PolicyMatch { EventCategories = ["authentication"] }
            }
        };
        DeterministicPolicyEvaluator evaluator = new([categoryOnly]);

        Bower.Abstractions.PolicyDecision decision = evaluator.Evaluate(
            TestEvents.AuthenticationFailure(TestEvents.Now) with { EventType = "brand_new_type" });

        Assert.Equal(Bower.Contracts.DecisionAction.Reject, decision.Action);
        Assert.Equal("BWR-POL-DEFAULT-DENY", decision.PolicyId);
    }

    /// <summary><see cref="ValidPolicy"/> hash, as pinned for the Rust port.</summary>
    private const string ValidPolicyHash =
        "sha256:664c378a9e14a0b601d8ae8c19ca1dcc25ed1e57d04bba94ff38bf671edf7191";

    private const string ValidPolicy =
        """
        apiVersion: bower.security/v1
        kind: TelemetryPolicy
        metadata:
          id: BWR-POL-TEST
          name: Test policy
          version: 1.0.0
          owner: Test
        match:
          eventTypes:
            - authentication_failure
        requirements:
          requiredFields:
            - eventType
        decision:
          action: accept
          minimumValueScore: 1
          neverSample: true
        """;

    private static string WritePolicy(TemporaryDirectory directory, string yaml)
    {
        string path = Path.Combine(directory.Path, "policy.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }
}
