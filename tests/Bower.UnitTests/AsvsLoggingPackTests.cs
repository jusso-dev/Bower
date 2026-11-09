using System.Text.Json;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// packs/owasp-asvs-app-logging: signs, passes its samples, composes with policies/default
/// without overlapping it, and redacts the injection and secret cases V16.2.5 and V16.4.1
/// care about. docs/security/asvs-logging-pack.md is the contract these tests hold.
/// </summary>
public sealed class AsvsLoggingPackTests
{
    private const string PackId = "owasp-asvs-app-logging";

    // Event types the pack owns. Changing this list is a population change: bump the pack
    // and policy versions and update the catalogue.
    private static readonly string[] PackEventTypes =
    [
        "authentication_success", "mfa_challenge", "mfa_success", "mfa_failure",
        "mfa_factor_enrolled", "mfa_factor_removed", "password_reset_requested", "password_reset_completed", "password_changed",
        "account_status_changed", "session_terminated", "session_rotated", "authorisation_failure",
        "sensitive_data_accessed", "sensitive_record_changed", "admin_action", "configuration_changed", "permission_changed",
        "input_validation_failure", "business_logic_violation", "anti_automation_triggered",
        "telemetry_aggregation_summary", "application_error", "security_control_failure", "database_audit"
    ];

    [Fact]
    public void Pack_BuildsSignsAndPassesEverySample()
    {
        LoadedPack pack = Build();

        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

        Assert.Equal(PackId, pack.Manifest.Id);
        Assert.Equal(12, pack.Policies.Count);
        Assert.Equal(3, pack.Detections.Count);
        Assert.NotNull(pack.PrivacyProfileYaml);
        Assert.NotNull(pack.DcrTemplateJson);
        Assert.True(results.Count >= 30);
        Assert.All(results, result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
        // Accept, quarantine and default-deny paths are all exercised.
        Assert.Contains(results, result => result.ExpectedDecision == "quarantine");
        Assert.Contains(results, result => result.ExpectedDecision == "reject");
    }

    [Fact]
    public void Samples_ExerciseEveryPolicyWithAnAcceptedEvent()
    {
        LoadedPack pack = Build();
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);
        HashSet<string> accepted = new(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "packs", PackId, "samples", "asvs.jsonl")))
        {
            using JsonDocument sample = JsonDocument.Parse(line);
            if (sample.RootElement.GetProperty("expect").GetString() != "accept")
            {
                continue;
            }

            string json = sample.RootElement.GetProperty("event").GetRawText().Replace("{{now}}", TestEvents.Now.ToString("O"), StringComparison.Ordinal);
            SecurityEventEnvelope envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(json, BowerJson.Options)!;
            accepted.Add(evaluator.Evaluate(envelope).PolicyId);
        }

        Assert.All(
            pack.Policies.Select(policy => policy.Policy.Metadata.Id).Where(id => id != "BWR-PACK-ASVS-SUPPRESSION-SUMMARY"),
            id => Assert.Contains(id, accepted));
    }

    [Fact]
    public void Pack_ComposesWithDefaultPoliciesWithoutOverlap()
    {
        LoadedPack pack = Build();
        IReadOnlyList<LoadedPolicy> defaults = PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "policies", "default"));
        HashSet<string> defaultTypes = defaults.SelectMany(policy => policy.Policy.Match.EventTypes).ToHashSet(StringComparer.Ordinal);
        string[] packTypes = [.. pack.Policies.SelectMany(policy => policy.Policy.Match.EventTypes).Order(StringComparer.Ordinal)];

        Assert.Equal(PackEventTypes.Order(StringComparer.Ordinal), packTypes);
        Assert.Empty(packTypes.Intersect(defaultTypes, StringComparer.Ordinal));
        Assert.Empty(pack.Policies.Select(policy => policy.Policy.Metadata.Id)
            .Intersect(defaults.Select(policy => policy.Policy.Metadata.Id), StringComparer.Ordinal));
        Assert.All(pack.Policies, policy => Assert.StartsWith("BWR-PACK-ASVS-", policy.Policy.Metadata.Id, StringComparison.Ordinal));
        Assert.All(pack.Policies, policy => Assert.Equal("1.0.0", policy.Policy.Metadata.Version));
    }

    [Fact]
    public void Pack_OnlyTheAntiAutomationFamilyIsSuppressedAndNothingIsSampled()
    {
        LoadedPack pack = Build();

        LoadedPolicy suppressed = Assert.Single(pack.Policies, policy => policy.Policy.Suppression is not null);
        Assert.Equal("BWR-PACK-ASVS-CONTROL-BYPASS", suppressed.Policy.Metadata.Id);
        Assert.All(pack.Policies, policy => Assert.Equal("accept", policy.Policy.Decision.Action));
        Assert.All(pack.Policies.Where(policy => policy.Policy.Suppression is null), policy => Assert.True(policy.Policy.Decision.NeverSample));
    }

    [Theory]
    [InlineData("actor.username", "alice\r\nINFO forged entry")]
    [InlineData("eventOutcomeReason", "ok\nWARN user=root")]
    [InlineData("labels.route", "/a\r/b")]
    public void PrivacyProfile_ReplacesLineBreaksEverywhere(string path, string value)
    {
        string redacted = Redact(EventWith(path, value));

        Assert.DoesNotContain('\r', redacted);
        Assert.DoesNotContain('\n', redacted);
        Assert.DoesNotContain("\\r", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("\\n", redacted, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("otpCode", "493021")]
    [InlineData("recoveryCode", "ABCD-EFGH-1234")]
    [InlineData("password", "correct horse battery staple")]
    [InlineData("stackTrace", "at Billing.Charge() secret-ish-text")]
    [InlineData("statement", "SELECT * FROM users WHERE email = 'jane@example.com'")]
    [InlineData("cookie", "sid=abc")]
    [InlineData("rawBody", "{\"x\":1}")]
    public void PrivacyProfile_RemovesSecretFieldsByName(string field, string value)
    {
        string redacted = Redact(EventWith($"attributes.{field}", value));

        Assert.DoesNotContain(value, redacted, StringComparison.Ordinal);
        using JsonDocument document = JsonDocument.Parse(redacted);
        Assert.False(document.RootElement.TryGetProperty("attributes", out JsonElement attributes)
            && attributes.TryGetProperty(field, out _));
    }

    [Fact]
    public void PrivacyProfile_PseudonymisesUsernameAndSessionDeterministically()
    {
        string first = Redact(EventWith("request.sessionId", "s%3Aq9XkLm2PzR7vT1yB4nC8dF0gH"));
        string second = Redact(EventWith("request.sessionId", "s%3Aq9XkLm2PzR7vT1yB4nC8dF0gH"));

        Assert.DoesNotContain("q9XkLm2PzR7vT1yB4nC8dF0gH", first, StringComparison.Ordinal);
        Assert.DoesNotContain("alice@example.com", first, StringComparison.Ordinal);
        Assert.Contains("hmac-sha256:k1:", first, StringComparison.Ordinal);
        // Same key, same input, same pseudonym: spraying analytics can still join attempts.
        Assert.Equal(first, second);
    }

    private static string EventWith(string path, string value)
    {
        Dictionary<string, object?> root = new()
        {
            ["schemaVersion"] = "1.0.0",
            ["eventId"] = "asvs-test-1",
            ["timeGenerated"] = TestEvents.Now.ToString("O"),
            ["eventCategory"] = "authentication",
            ["eventType"] = "mfa_failure",
            ["eventAction"] = "mfa.verify",
            ["eventResult"] = "failure",
            ["application"] = new Dictionary<string, object?> { ["name"] = "contoso-portal", ["environment"] = "test" },
            ["actor"] = new Dictionary<string, object?> { ["userId"] = "user-1", ["username"] = "alice@example.com" },
            ["request"] = new Dictionary<string, object?> { ["correlationId"] = "req-1" },
            ["labels"] = new Dictionary<string, object?> { ["mfaFactor"] = "totp" },
            ["attributes"] = new Dictionary<string, object?>()
        };
        string[] segments = path.Split('.');
        if (segments.Length == 1)
        {
            root[segments[0]] = value;
        }
        else
        {
            ((Dictionary<string, object?>)root[segments[0]]!)[segments[1]] = value;
        }

        return JsonSerializer.Serialize(root);
    }

    private static string Redact(string json)
    {
        string yaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "packs", PackId, "privacy.yaml"));
        PrivacyEngine engine = new(PrivacyProfileLoader.Load(yaml, new byte[32], "k1").Policy);
        return engine.RedactJson(json).RedactedJson!;
    }

    private static LoadedPack Build()
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", PackId), privatePem, output.Path);
        return PackArchive.Load(archive, [publicPem]);
    }
}
