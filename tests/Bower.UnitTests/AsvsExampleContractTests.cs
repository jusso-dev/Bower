using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// examples/asvs-logging/contract: the events every framework helper (Node, Python, Go, Ruby,
/// PHP, Java, C#) must produce from contract/cases.json. Those helpers are checked against
/// expected.jsonl by examples/asvs-logging/check.sh; this test checks expected.jsonl itself
/// against the envelope schema, the shipped policies and the ASVS pack privacy profile,
/// with no extra toolchain in the main CI.
/// </summary>
public sealed partial class AsvsExampleContractTests
{
    private static string Root => Path.Combine(AppContext.BaseDirectory, "examples", "asvs-logging", "contract");

    private static IEnumerable<JsonElement> ExpectedEvents()
    {
        foreach (string line in File.ReadLines(Path.Combine(Root, "expected.jsonl")))
        {
            JsonElement row = JsonDocument.Parse(line).RootElement;
            if (!row.TryGetProperty("clientIp", out _))
            {
                yield return row;
            }
        }
    }

    [Fact]
    public void ExpectedEvents_MatchTheEnvelopeSchema()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "schemas", "envelope", "security-event.schema.json")));
        List<JsonElement> events = [.. ExpectedEvents()];

        Assert.Equal(8, events.Count);
        foreach (JsonElement envelope in events)
        {
            List<string> errors = [];
            Validate(envelope, schema.RootElement, schema.RootElement, "$", errors);
            Assert.True(errors.Count == 0, $"{envelope.GetProperty("eventId")}: {string.Join("; ", errors)}");
            Assert.Matches(UtcMillis(), envelope.GetProperty("timeGenerated").GetString());
        }
    }

    [Fact]
    public void ExpectedEvents_CarryNoSecretsLineBreaksOrQueryStrings()
    {
        string text = File.ReadAllText(Path.Combine(Root, "expected.jsonl"));

        foreach (string secret in new[] { "hunter2", "eyJhbGciOiJIUzI1NiJ9", "abc123", "493021", "sk_live_51Hx", "previousValue", "newValue", "\\r", "\\n", "?next=" })
        {
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        }

        // The inputs deliberately contain them, so the helpers did the removing.
        string cases = File.ReadAllText(Path.Combine(Root, "cases.json"));
        Assert.Contains("hunter2", cases, StringComparison.Ordinal);
        Assert.Contains("\\r\\n", cases, StringComparison.Ordinal);
    }

    [Fact]
    public void ExpectedEvents_AreAcceptedByTheShippedPoliciesAndPackAfterRedaction()
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        LoadedPack pack = PackArchive.Load(
            PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", "owasp-asvs-app-logging"), privatePem, output.Path), [publicPem]);
        DeterministicPolicyEvaluator evaluator = new([.. PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "policies", "default")), .. pack.Policies]);
        PrivacyEngine engine = new(PrivacyProfileLoader.Load(pack.PrivacyProfileYaml!, new byte[32], "k1").Policy);

        foreach (JsonElement envelope in ExpectedEvents())
        {
            string json = envelope.GetRawText().Replace("2026-11-09T01:02:03.456Z", TestEvents.Now.ToString("O"), StringComparison.Ordinal);
            string redacted = engine.RedactJson(json).RedactedJson!;
            SecurityEventEnvelope candidate = JsonSerializer.Deserialize<SecurityEventEnvelope>(redacted, BowerJson.Options)!;
            PolicyDecision decision = evaluator.Evaluate(candidate);

            Assert.True(
                decision.Action is DecisionAction.Accept or DecisionAction.RedactAndAccept,
                $"{candidate.EventId} ({candidate.EventType}): {decision.Action} {string.Join("; ", decision.Reasons)}");
            Assert.DoesNotContain("alice@example.com", redacted, StringComparison.Ordinal);
            Assert.DoesNotContain("sess-7f3a", redacted, StringComparison.Ordinal);
        }
    }

    // Structural JSON Schema subset the envelope uses: type, required, properties,
    // additionalProperties (bool or schema), enum, const, pattern, minLength, maxLength,
    // minimum, maximum, maxProperties, oneOf and local $ref. Anything else fails loudly.
    private static void Validate(JsonElement value, JsonElement schema, JsonElement root, string path, List<string> errors)
    {
        if (schema.TryGetProperty("$ref", out JsonElement reference))
        {
            string name = reference.GetString()!.Replace("#/$defs/", string.Empty, StringComparison.Ordinal);
            Validate(value, root.GetProperty("$defs").GetProperty(name), root, path, errors);
            return;
        }

        if (schema.TryGetProperty("oneOf", out JsonElement oneOf))
        {
            int matches = oneOf.EnumerateArray().Count(option =>
            {
                List<string> attempt = [];
                Validate(value, option, root, path, attempt);
                return attempt.Count == 0;
            });
            if (matches != 1)
            {
                errors.Add($"{path}: matches {matches} oneOf options");
            }

            return;
        }

        foreach (JsonProperty keyword in schema.EnumerateObject())
        {
            switch (keyword.Name)
            {
                case "type":
                    string[] types = keyword.Value.ValueKind == JsonValueKind.Array
                        ? [.. keyword.Value.EnumerateArray().Select(t => t.GetString()!)]
                        : [keyword.Value.GetString()!];
                    if (!types.Any(type => IsType(value, type)))
                    {
                        errors.Add($"{path}: expected {string.Join("|", types)}");
                        return;
                    }

                    break;
                case "const" when value.GetRawText() != keyword.Value.GetRawText():
                    errors.Add($"{path}: not the constant {keyword.Value}");
                    break;
                case "enum" when !keyword.Value.EnumerateArray().Any(option => option.GetRawText() == value.GetRawText()):
                    errors.Add($"{path}: not in enum");
                    break;
                case "pattern" when value.ValueKind == JsonValueKind.String && !Regex.IsMatch(value.GetString()!, keyword.Value.GetString()!):
                    errors.Add($"{path}: does not match {keyword.Value}");
                    break;
                case "minLength" when value.ValueKind == JsonValueKind.String && value.GetString()!.Length < keyword.Value.GetInt32():
                case "maxLength" when value.ValueKind == JsonValueKind.String && value.GetString()!.Length > keyword.Value.GetInt32():
                case "minimum" when value.ValueKind == JsonValueKind.Number && value.GetDouble() < keyword.Value.GetDouble():
                case "maximum" when value.ValueKind == JsonValueKind.Number && value.GetDouble() > keyword.Value.GetDouble():
                case "maxProperties" when value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Count() > keyword.Value.GetInt32():
                    errors.Add($"{path}: violates {keyword.Name} {keyword.Value}");
                    break;
                case "required" when value.ValueKind == JsonValueKind.Object:
                    foreach (JsonElement name in keyword.Value.EnumerateArray())
                    {
                        if (!value.TryGetProperty(name.GetString()!, out _))
                        {
                            errors.Add($"{path}: missing {name}");
                        }
                    }

                    break;
                case "properties" or "additionalProperties" when value.ValueKind == JsonValueKind.Object:
                    if (keyword.Name == "additionalProperties")
                    {
                        break; // handled with properties below
                    }

                    foreach (JsonProperty member in value.EnumerateObject())
                    {
                        string child = $"{path}.{member.Name}";
                        if (keyword.Value.TryGetProperty(member.Name, out JsonElement memberSchema))
                        {
                            Validate(member.Value, memberSchema, root, child, errors);
                        }
                        else if (schema.TryGetProperty("additionalProperties", out JsonElement extra))
                        {
                            if (extra.ValueKind == JsonValueKind.False)
                            {
                                errors.Add($"{child}: not allowed");
                            }
                            else if (extra.ValueKind == JsonValueKind.Object)
                            {
                                Validate(member.Value, extra, root, child, errors);
                            }
                        }
                    }

                    break;
                case "type" or "const" or "enum" or "pattern" or "minLength" or "maxLength" or "minimum" or "maximum"
                    or "maxProperties" or "required" or "properties" or "additionalProperties"
                    or "$schema" or "$id" or "title" or "description" or "format" or "$defs" or "x-bower-classification":
                    break;
                default:
                    errors.Add($"{path}: validator does not support keyword {keyword.Name}");
                    break;
            }
        }

        // An object schema with additionalProperties but no properties keyword (labels).
        if (value.ValueKind == JsonValueKind.Object && !schema.TryGetProperty("properties", out _)
            && schema.TryGetProperty("additionalProperties", out JsonElement only) && only.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty member in value.EnumerateObject())
            {
                Validate(member.Value, only, root, $"{path}.{member.Name}", errors);
            }
        }
    }

    private static bool IsType(JsonElement value, string type) => type switch
    {
        "object" => value.ValueKind == JsonValueKind.Object,
        "array" => value.ValueKind == JsonValueKind.Array,
        "string" => value.ValueKind == JsonValueKind.String,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
        "number" => value.ValueKind == JsonValueKind.Number,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "null" => value.ValueKind == JsonValueKind.Null,
        _ => false,
    };

    [Fact]
    public void Validator_RejectsBrokenEnvelopes()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "schemas", "envelope", "security-event.schema.json")));
        string good = ExpectedEvents().First().GetRawText();
        foreach ((string from, string to) in new[]
        {
            ("\"schemaVersion\": \"1.0.0\"", "\"schemaVersion\": \"2.0.0\""),
            ("\"eventResult\": \"success\"", "\"eventResult\": \"ok\""),
            ("\"eventType\": \"authentication_success\"", "\"eventType\": \"Auth Success\""),
            ("\"labels\": {", "\"unknownTop\": 1, \"labels\": {"),
            ("\"statusCode\": 200", "\"statusCode\": 999"),
        })
        {
            Assert.Contains(from, good, StringComparison.Ordinal);
            List<string> errors = [];
            Validate(JsonDocument.Parse(good.Replace(from, to, StringComparison.Ordinal)).RootElement, schema.RootElement, schema.RootElement, "$", errors);
            Assert.NotEmpty(errors);
        }
    }

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")]
    private static partial Regex UtcMillis();
}
