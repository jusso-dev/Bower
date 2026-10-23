using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;

namespace Bower.Packs;

public sealed record PackSampleResult(string Name, bool Passed, string ExpectedDecision, string ActualDecision, IReadOnlyList<string> Problems);

/// <summary>
/// Runs a pack's samples through redaction and policy exactly as a collector would, and
/// checks the expected decision and that listed sensitive strings never survive.
/// Sample lines: {"name": "...", "expect": "accept", "mustNotContain": ["..."], "event": {...}}.
/// "{{now}}" in the event is replaced with the current UTC time.
/// Expectations: "accept" passes for accept and for redact-and-accept, because the event
/// is delivered either way (prove the redaction with "mustNotContain"); "redact-and-accept"
/// requires that redaction happened; every other expectation must match exactly.
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
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);
        PackDetectionRedactor engine = new(new JsonEventRedactor(privacy), evaluator, pack.Detections);
        List<PackSampleResult> results = [];
        int index = 0;
        foreach (string line in pack.SampleLines)
        {
            index++;
            JsonObject sample = JsonNode.Parse(line) as JsonObject
                ?? throw new InvalidDataException($"Sample {index} is not a JSON object.");
            string name = sample["name"]?.GetValue<string>() ?? $"sample-{index}";
            string expected = (sample["expect"]?.GetValue<string>() ?? "accept").Replace("-", string.Empty, StringComparison.Ordinal);
            List<string> problems = [];
            string? eventJson;
            if (sample["raw"] is { } raw)
            {
                int parser = sample["parser"]?.GetValue<int>() ?? throw new InvalidDataException("Raw samples require a parser index.");
                if (parser < 0 || parser >= pack.Parsers.Count)
                {
                    throw new InvalidDataException("Raw sample parser index is invalid.");
                }

                SecurityEventEnvelope? mapped = PackRuntime.Parse(pack.Parsers[parser],
                    raw.ToJsonString().Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal));
                eventJson = mapped is null ? null : JsonSerializer.Serialize(mapped, BowerJson.Envelope);
            }
            else
            {
                eventJson = (sample["event"] ?? throw new InvalidDataException($"Sample '{name}' has no event."))
                    .ToJsonString().Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal);
            }

            RedactionResult redaction = eventJson is null
                ? new RedactionResult(false, null, [], [], "not-selected") : engine.Redact(eventJson);
            string actual;
            string[] detected = [];
            if (eventJson is null)
            {
                actual = "reject";
            }
            else if (!redaction.Succeeded)
            {
                actual = "quarantine";
            }
            else
            {
                SecurityEventEnvelope? envelope = JsonSerializer.Deserialize(redaction.RedactedJson!, BowerJson.Envelope);
                PolicyDecision decision = evaluator.Evaluate(envelope!);
                actual = decision.Action switch
                {
                    DecisionAction.Accept when redaction.RemovedPaths.Count + redaction.MaskedPaths.Count > 0
                        || redaction.PrivacyDetected?.Count > 0 => "redactandaccept",
                    _ => decision.Action.ToString().ToLowerInvariant()
                };

                if (envelope!.Attributes?.TryGetValue(PackDetectionRedactor.EvidenceAttribute, out JsonElement evidence) == true)
                {
                    detected = evidence.EnumerateArray().Select(item => item.GetProperty("ruleId").GetString()!).ToArray();
                }

                foreach (string forbidden in (sample["mustNotContain"] as JsonArray)?.Select(item => item!.GetValue<string>()) ?? [])
                {
                    if (redaction.RedactedJson!.Contains(forbidden, StringComparison.Ordinal))
                    {
                        problems.Add($"Redacted event still contains a forbidden value ({forbidden.Length} characters).");
                    }
                }
            }

            if (sample["expectedDetections"] is JsonArray expectedDetections
                && !expectedDetections.Select(item => item!.GetValue<string>()).Order(StringComparer.Ordinal)
                    .SequenceEqual(detected.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            {
                problems.Add("Expected detection rule ids do not match local execution.");
            }

            // "accept" also covers redact-and-accept; the reverse does not hold.
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
