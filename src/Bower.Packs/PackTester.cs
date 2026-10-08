using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.Packs;

public sealed record PackSampleResult(string Name, bool Passed, string ExpectedDecision, string ActualDecision, IReadOnlyList<string> Problems);

/// <summary>
/// Runs a pack's samples through redaction and policy exactly as a collector would, and
/// checks the expected decision and that listed sensitive strings never survive.
/// Sample lines: {"name": "...", "expect": "accept", "mustNotContain": ["..."], "event": {...}}.
/// "{{now}}" in the event is replaced with the current UTC time.
/// </summary>
public static class PackTester
{
    public static IReadOnlyList<PackSampleResult> Run(
        LoadedPack pack,
        PrivacyPolicy privacy,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(pack);
        DateTimeOffset now = (clock ?? TimeProvider.System).GetUtcNow();
        PrivacyEngine engine = new(privacy);
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);
        List<PackSampleResult> results = [];
        int index = 0;
        foreach (string line in pack.SampleLines)
        {
            index++;
            JsonObject sample = JsonNode.Parse(line) as JsonObject
                ?? throw new InvalidDataException($"Sample {index} is not a JSON object.");
            string name = sample["name"]?.GetValue<string>() ?? $"sample-{index}";
            string expected = (sample["expect"]?.GetValue<string>() ?? "accept").Replace("-", string.Empty, StringComparison.Ordinal);
            string eventJson = (sample["event"] ?? throw new InvalidDataException($"Sample '{name}' has no event."))
                .ToJsonString()
                .Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal);
            List<string> problems = [];

            PrivacyScanResult redaction = engine.RedactJson(eventJson);
            string actual;
            if (!redaction.Succeeded)
            {
                actual = "quarantine";
            }
            else
            {
                SecurityEventEnvelope? envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(
                    redaction.RedactedJson!, BowerJson.Options);
                PolicyDecision decision = evaluator.Evaluate(envelope!);
                actual = decision.Action switch
                {
                    DecisionAction.Accept when redaction.Findings.Count > 0 => "redactandaccept",
                    _ => decision.Action.ToString().ToLowerInvariant()
                };

                foreach (string forbidden in (sample["mustNotContain"] as JsonArray)?.Select(item => item!.GetValue<string>()) ?? [])
                {
                    if (redaction.RedactedJson!.Contains(forbidden, StringComparison.Ordinal))
                    {
                        problems.Add($"Redacted event still contains a forbidden value ({forbidden.Length} characters).");
                    }
                }
            }

            bool decisionMatches = string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)
                || (expected.Equals("accept", StringComparison.OrdinalIgnoreCase) && actual == "redactandaccept");
            if (!decisionMatches)
            {
                problems.Add($"Expected {expected}, got {actual}.");
            }

            results.Add(new PackSampleResult(name, problems.Count == 0, expected, actual, problems));
        }

        return results;
    }
}
