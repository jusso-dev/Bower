using System.Text.Json;
using Bower.Contracts;
using Bower.Detection;

namespace Bower.UnitTests;

public sealed class DetectionSemanticsTests
{
    [Fact]
    public void SharedVectors_PinBooleanPrecedenceTypedEqualityAndRejectedGrammar()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "detection-vectors", "semantics.json")));
        foreach (JsonElement vector in document.RootElement.EnumerateArray())
        {
            string yaml = vector.GetProperty("yaml").GetString()!;
            string name = vector.GetProperty("name").GetString()!;
            if (!vector.GetProperty("valid").GetBoolean())
            {
                Exception? failure = Record.Exception(() => SigmaRuleLoader.LoadYaml(yaml));
                Assert.True(failure is not null, name);
                continue;
            }

            DetectionRule rule = SigmaRuleLoader.LoadYaml(yaml);
            SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(TestEvents.Now) with
            {
                Labels = vector.GetProperty("labels").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!),
                Attributes = vector.GetProperty("attributes").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())
            };
            if (vector.TryGetProperty("evaluationFailure", out JsonElement evaluationFailure) && evaluationFailure.GetBoolean())
            {
                Assert.Throws<InvalidDataException>(() => new DetectionEngine([rule]).Evaluate(envelope));
                continue;
            }
            bool match = new DetectionEngine([rule]).Evaluate(envelope).Alerts.Count == 1;
            Assert.True(match == vector.GetProperty("match").GetBoolean(), name);
        }
    }

    [Fact]
    public void ShippedRuleVectors_MatchCSharpEncodingAndHashes()
    {
        string[] files = [
            "aws-security/detections/aws-access-key-created.yml",
            "aws-security/detections/aws-console-login-failure.yml",
            "aws-security/detections/aws-logging-tampering.yml",
            "aws-security/detections/aws-root-activity.yml",
            "gcp-security/detections/gcp-iam-policy-changed.yml",
            "gcp-security/detections/gcp-logging-tampering.yml",
            "gcp-security/detections/gcp-permission-denied.yml",
            "gcp-security/detections/gcp-service-account-key-created.yml",
            "linux-ssh-gateway/detections/ssh-password-spray.yml"
        ];
        DetectionRule[] rules = [.. files.Select(file => SigmaRuleLoader.LoadFile(Path.Combine(AppContext.BaseDirectory, "packs", file))),
            SigmaRuleLoader.LoadFile(Path.Combine(AppContext.BaseDirectory, "rules", "sigma", "auth_failure_burst.yml"))];
        string[] vectors = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "detection-vectors", "sigma.jsonl"));
        Assert.Equal(rules.Length, vectors.Length);
        for (int index = 0; index < rules.Length; index++)
        {
            using JsonDocument vector = JsonDocument.Parse(vectors[index]);
            Assert.Equal(rules[index].RuleHash, vector.RootElement.GetProperty("RuleHash").GetString());
            Assert.Equal(rules[index].Condition, vector.RootElement.GetProperty("Condition").GetString());
            foreach ((string key, string value) in rules[index].DetectionFields)
            {
                Assert.Equal(value, vector.RootElement.GetProperty("DetectionFields").GetProperty(key).GetString());
            }
        }
    }
}
