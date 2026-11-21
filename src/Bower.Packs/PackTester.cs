using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Pipeline;
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
/// Multi-line samples use "rawLines" (an array of raw text lines) with "parser" and optional
/// "expectEvents" (default 1): lines are merged through the parser's multiline rule before
/// parsing, transforms and redaction, so secrets split across lines are caught as one value.
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
        "name", "expect", "event", "raw", "rawLines", "expectEvents", "parser", "mustNotContain", "expectedDetections", "expectFields"
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
            bool hasEvent = sample["event"] is not null;
            bool hasRaw = sample["raw"] is not null;
            bool hasRawLines = sample["rawLines"] is not null;
            if ((hasEvent ? 1 : 0) + (hasRaw ? 1 : 0) + (hasRawLines ? 1 : 0) != 1)
            {
                throw new InvalidDataException($"Sample {index} must specify exactly one of 'event', 'raw' or 'rawLines'.");
            }

            if (sample["expectEvents"] is not null && !hasRawLines)
            {
                throw new InvalidDataException($"Sample {index} 'expectEvents' is only valid with 'rawLines'.");
            }

            int? sampleParser = !hasRaw && !hasRawLines ? null : SampleParser(pack, sample["parser"]);
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
            if (hasRawLines)
            {
                CustomLogParserConfiguration parserConfig = pack.Parsers[sampleParser!.Value];
                string[] rawLines = ReadRawLines(sample["rawLines"]!, name, now);
                int expectedEvents = ReadExpectedEvents(sample["expectEvents"], name);
                string[] mergedTexts = parserConfig.Multiline is { } multiline
                    ? MultilineLineMerger.MergeAll(multiline, rawLines, now).Select(item => item.Text).ToArray()
                    : rawLines;
                if (mergedTexts.Length != expectedEvents)
                {
                    problems.Add($"Expected {expectedEvents} merged event(s), got {mergedTexts.Length}.");
                }

                List<string> actualDecisions = [];
                string[] forbiddenValues = (sample["mustNotContain"] as JsonArray)?.Select(item => item!.GetValue<string>()).ToArray() ?? [];
                string[]? expectedDetectionsList = (sample["expectedDetections"] as JsonArray)?.Select(item => item!.GetValue<string>()).ToArray();
                for (int mergedIndex = 0; mergedIndex < mergedTexts.Length; mergedIndex++)
                {
                    JsonObject recordObject = new()
                    {
                        ["id"] = $"sample-ml-{index}-{mergedIndex + 1}",
                        ["message"] = mergedTexts[mergedIndex],
                        ["readAt"] = now.ToString("O")
                    };
                    string mergedRaw = recordObject.ToJsonString();
                    string? mergedFailure = null;
                    SecurityEventEnvelope? mapped = null;
                    try
                    {
                        mapped = PackRuntime.Parse(parserConfig, mergedRaw, now);
                    }
                    catch (TransformException exception)
                    {
                        mergedFailure = exception.Code;
                    }

                    string? mergedEventJson = mapped is null ? null : JsonSerializer.Serialize(mapped, BowerJson.Envelope);
                    string decision = EvaluateEvent(
                        engine,
                        evaluator,
                        mergedEventJson,
                        mergedRaw,
                        mergedFailure,
                        expected,
                        forbiddenValues,
                        expectations,
                        expectedDetectionsList,
                        problems);
                    actualDecisions.Add(decision);
                }

                string summaryActual = actualDecisions.Count == 0 ? "none" : actualDecisions[^1];
                results.Add(new PackSampleResult(name, problems.Count == 0, expected, summaryActual, problems));
                continue;
            }
            else if (sample["raw"] is { } raw)
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

            string[] singleForbiddenValues = (sample["mustNotContain"] as JsonArray)?.Select(item => item!.GetValue<string>()).ToArray() ?? [];
            string[]? singleExpectedDetections = (sample["expectedDetections"] as JsonArray)?.Select(item => item!.GetValue<string>()).ToArray();
            string actual = EvaluateEvent(
                engine,
                evaluator,
                eventJson,
                rawJson,
                transformFailure,
                expected,
                singleForbiddenValues,
                expectations,
                singleExpectedDetections,
                problems);

            results.Add(new PackSampleResult(name, problems.Count == 0, expected, actual, problems));
        }

        return results;
    }

    private static string EvaluateEvent(
        PackDetectionRedactor engine,
        DeterministicPolicyEvaluator evaluator,
        string? eventJson,
        string? rawJson,
        string? transformFailure,
        string expected,
        string[] forbiddenValues,
        IReadOnlyList<PackFieldExpectation>? expectations,
        string[]? expectedDetections,
        List<string> problems)
    {
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

        if (expectedDetections is not null
            && !expectedDetections.Order(StringComparer.Ordinal)
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

        return actual;
    }

    private static string[] ReadRawLines(JsonNode node, string sampleName, DateTimeOffset now)
    {
        if (node is not JsonArray array || array.Count is < 1 or > CustomLogMultilineRule.MaximumMaxLines)
        {
            throw new InvalidDataException(
                $"Sample '{sampleName}' 'rawLines' must be an array of 1 to {CustomLogMultilineRule.MaximumMaxLines} strings.");
        }

        string nowText = now.ToString("O");
        string[] lines = new string[array.Count];
        for (int index = 0; index < array.Count; index++)
        {
            if (array[index] is not JsonValue value || value.GetValueKind() != JsonValueKind.String)
            {
                throw new InvalidDataException($"Sample '{sampleName}' 'rawLines[{index}]' must be a string.");
            }

            lines[index] = value.GetValue<string>().Replace("{{now}}", nowText, StringComparison.Ordinal);
        }

        return lines;
    }

    private static int ReadExpectedEvents(JsonNode? node, string sampleName)
    {
        if (node is null)
        {
            return 1;
        }

        if (node is not JsonValue value || value.GetValueKind() != JsonValueKind.Number || !value.TryGetValue(out int count) || count < 1)
        {
            throw new InvalidDataException($"Sample '{sampleName}' 'expectEvents' must be an integer of at least 1.");
        }

        return count;
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
