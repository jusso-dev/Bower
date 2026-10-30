using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Pipeline.Transforms;
using Bower.PolicyEngine;
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
            string? eventJson;
            bool transformFailed = false;
            if (sample["raw"] is JsonNode raw)
            {
                int parser = sample["parser"]?.GetValue<int>()
                    ?? throw new InvalidDataException("Raw sample has no parser index.");
                if (parser < 0 || parser >= pack.Parsers.Count || pack.Parsers[parser].Runtime is null)
                {
                    throw new InvalidDataException("Raw sample requires an active runtime parser.");
                }
                SecurityEventEnvelope? mapped = null;
                try
                {
                    mapped = PackRuntime.Parse(pack.Parsers[parser],
                        raw.ToJsonString().Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal), now);
                }
                catch (TransformException)
                {
                    transformFailed = true;
                }
                eventJson = mapped is null ? null : JsonSerializer.Serialize(mapped, BowerJson.Envelope);
            }
            else
            {
                eventJson = (sample["event"] ?? throw new InvalidDataException($"Sample '{name}' has no event."))
                    .ToJsonString().Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal);
            }
            List<string> problems = [];

            PrivacyScanResult redaction = engine.RedactJson(eventJson ?? "null");
            string actual;
            if (transformFailed)
            {
                actual = "quarantine";
            }
            else if (eventJson is null)
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
                if (sample["expectFields"] is JsonObject fields)
                {
                    JsonNode? redacted = JsonNode.Parse(redaction.RedactedJson!);
                    foreach ((string path, JsonNode? expectation) in fields)
                    {
                        JsonNode? value = redacted;
                        foreach (string segment in path.Split('.'))
                        {
                            value = (value as JsonObject)?[segment];
                        }
                        string expectedValue = expectation?.GetValue<string>()
                            ?? throw new InvalidDataException("Expected field value must be a string.");
                        bool matches = expectedValue switch
                        {
                            "present" => value is not null,
                            "absent" => value is null,
                            _ => value is JsonValue scalar && scalar.TryGetValue<string>(out string? text)
                                && string.Equals(text, expectedValue, StringComparison.Ordinal)
                        };
                        if (!matches)
                        {
                            problems.Add($"Expected field '{path}' did not match.");
                        }
                    }
                }
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
