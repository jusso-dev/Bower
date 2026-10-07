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

        Assert.Equal(2, policies.Count);
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
