using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Pipeline.Transforms;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;

namespace Bower.Packs;

public sealed record PackSampleResult(string Name, bool Passed, string ExpectedDecision, string ActualDecision, IReadOnlyList<string> Problems);

/// <summary>
/// Runs a pack's samples through redaction and policy exactly as a collector would, and
/// checks the expected decision and that listed sensitive strings never survive.
/// Sample lines: {"name": "...", "expect": "accept", "mustNotContain": ["..."], "event": {...}}.
/// "{{now}}" in the event is replaced with the current UTC time. Raw samples run the
/// parser's transform program with that same time as its evaluation time; a transform
/// failure is decision "quarantine" (the record is never redacted, selected or kept).
/// Expectations: "accept" passes for accept and for redact-and-accept, because the event
/// is delivered either way (prove the redaction with "mustNotContain"); "redact-and-accept"
/// requires that redaction happened; every other expectation must match exactly.
/// "expectFields" asserts paths of the redacted event (<see cref="PackFieldAssertions"/>).
/// "parser" is a zero-based index or a parser name (file name without extension, or its
/// pack path). Unknown or duplicated sample members fail, so a mistyped assertion cannot
/// silently pass. Line format: <c>schemas/packs/pack-sample.schema.json</c> (v2).
/// </summary>
public static class PackTester
{
    private static readonly HashSet<string> Members = new(StringComparer.Ordinal)
    {
        "name", "expect", "event", "raw", "parser", "mustNotContain", "expectedDetections", "expectFields"
    };

    /// <param name="parser">Run only the raw samples of this parser (name or path); null runs every sample.</param>
    public static IReadOnlyList<PackSampleResult> Run(
        LoadedPack pack,
        PrivacyPolicy privacy,
        TimeProvider? clock = null,
        string? parser = null)
    {
        ArgumentNullException.ThrowIfNull(pack);
        int? only = parser is null ? null
            : ParserIndex(pack, parser) ?? throw new InvalidDataException($"Pack has no parser '{parser}'.");
        DateTimeOffset now = (clock ?? TimeProvider.System).GetUtcNow();
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);
        PackDetectionRedactor engine = new(new JsonEventRedactor(privacy), evaluator, pack.Detections);
        List<PackSampleResult> results = [];
        int index = 0;
        foreach (string line in pack.SampleLines)
        {
            index++;
            using JsonDocument document = JsonDocument.Parse(line);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"Sample {index} is not a JSON object.");
            }

            HashSet<string> seen = new(StringComparer.Ordinal);
            foreach (JsonProperty member in document.RootElement.EnumerateObject())
            {
                if (!Members.Contains(member.Name) || !seen.Add(member.Name))
                {
                    throw new InvalidDataException($"Sample {index} member '{member.Name}' is unknown or duplicated.");
                }
            }

            JsonObject sample = JsonNode.Parse(line)!.AsObject();
            int? sampleParser = sample["raw"] is null ? null : SampleParser(pack, sample["parser"]);
            if (only is not null && sampleParser != only)
            {
                continue;
            }

            string name = sample["name"]?.GetValue<string>() ?? $"sample-{index}";
            IReadOnlyList<PackFieldExpectation>? expectations = PackFieldAssertions.Parse(document.RootElement, name);
            string expected = (sample["expect"]?.GetValue<string>() ?? "accept").Replace("-", string.Empty, StringComparison.Ordinal);
            List<string> problems = [];
            string? eventJson;
            string? rawJson = null;
            string? transformFailure = null;
            if (sample["raw"] is { } raw)
            {
                SecurityEventEnvelope? mapped = null;
                rawJson = raw.ToJsonString().Replace("{{now}}", now.ToString("O"), StringComparison.Ordinal);
                try
                {
                    mapped = PackRuntime.Parse(pack.Parsers[sampleParser!.Value], rawJson, now);
                }
                catch (TransformException exception)
                {
                    // Quarantined before redaction, as a collector does; only the code is kept.
                    transformFailure = exception.Code;
                }

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
            if (transformFailure is not null)
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
                    DecisionAction.Accept when redaction.RemovedPaths.Count + redaction.MaskedPaths.Count > 0
                        || redaction.PrivacyDetected?.Count > 0 => "redactandaccept",
                    _ => decision.Action.ToString().ToLowerInvariant()
                };

                if (envelope!.Attributes?.TryGetValue(PackDetectionRedactor.EvidenceAttribute, out JsonElement evidence) == true)
                {
                    detected = evidence.EnumerateArray().Select(item => item.GetProperty("ruleId").GetString()!).ToArray();
                }

                string[] forbiddenValues = (sample["mustNotContain"] as JsonArray)?.Select(item => item!.GetValue<string>()).ToArray() ?? [];
                foreach (string forbidden in forbiddenValues)
                {
                    if (redaction.RedactedJson!.Contains(forbidden, StringComparison.Ordinal))
                    {
                        problems.Add($"Redacted event still contains a forbidden value ({forbidden.Length} characters).");
                    }
                }

                if (expectations is not null)
                {
                    // Pre-redaction inputs only identify withheld values; they are never echoed.
                    string[] inputs = rawJson is null ? [eventJson] : [rawJson, eventJson];
                    problems.AddRange(PackFieldAssertions.Check(expectations, redaction.RedactedJson!, inputs, forbiddenValues));
                }
            }

            if (expectations is not null && (transformFailure is not null || eventJson is null || !redaction.Succeeded))
            {
                problems.Add($"Field assertions need a redacted event; got {actual}.");
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
                if (transformFailure is not null)
                {
                    problems.Add($"Transform failed: {transformFailure}.");
                }
            }

            results.Add(new PackSampleResult(name, problems.Count == 0, expected, actual, problems));
        }

        return results;
    }

    /// <summary>
    /// Index of a parser by name (file name without extension) or pack path; null when no
    /// parser or more than one parser has that name.
    /// </summary>
    public static int? ParserIndex(LoadedPack pack, string name)
    {
        ArgumentNullException.ThrowIfNull(pack);
        int[] matches = Enumerable.Range(0, pack.ParserPaths.Count)
            .Where(index => pack.ParserPaths[index] == name || Path.GetFileNameWithoutExtension(pack.ParserPaths[index]) == name)
            .ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }

    private static int SampleParser(LoadedPack pack, JsonNode? parser)
    {
        if (parser is JsonValue value && value.GetValueKind() == JsonValueKind.String)
        {
            return ParserIndex(pack, value.GetValue<string>())
                ?? throw new InvalidDataException("Raw sample parser name is unknown or ambiguous.");
        }

        int index = parser?.GetValue<int>() ?? throw new InvalidDataException("Raw samples require a parser index.");
        return index >= 0 && index < pack.Parsers.Count ? index : throw new InvalidDataException("Raw sample parser index is invalid.");
    }
}
