using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bower.Packs;

/// <summary>One <c>expectFields</c> entry: a dotted path and the post-redaction expectation.</summary>
public sealed record PackFieldExpectation(string Path, IReadOnlyList<string> Segments, string Kind, JsonElement? Value)
{
    public const string Present = "present";
    public const string Absent = "absent";
    public const string Exact = "exact";
}

/// <summary>
/// Field-level sample assertions (<c>expectFields</c>), checked against the redacted event
/// only. An expectation can never name a value that redaction withheld: an expected string
/// that equals a pre-redaction value missing from the redacted event, or that contains a
/// <c>mustNotContain</c> entry, fails without the value being printed. Failure messages name
/// the path and show only post-redaction values (or the expectation, once proven safe).
/// </summary>
public static partial class PackFieldAssertions
{
    public const int MaximumExpectations = 64;
    public const int MaximumPathLength = 256;
    public const int MaximumSegments = 16;

    /// <summary>Parses and validates <c>expectFields</c>; <c>null</c> when the sample has none.</summary>
    public static IReadOnlyList<PackFieldExpectation>? Parse(JsonElement sample, string name)
    {
        if (!sample.TryGetProperty("expectFields", out JsonElement fields) || fields.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (fields.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"Sample '{name}' expectFields must be an object.");
        }

        List<PackFieldExpectation> expectations = [];
        HashSet<string> paths = new(StringComparer.Ordinal);
        foreach (JsonProperty field in fields.EnumerateObject())
        {
            string[] segments = field.Name.Split('.');
            if (field.Name.Length > MaximumPathLength || segments.Length > MaximumSegments
                || !segments.All(segment => Segment().IsMatch(segment)))
            {
                throw new InvalidDataException($"Sample '{name}' expectFields has an invalid path.");
            }

            if (!paths.Add(field.Name))
            {
                throw new InvalidDataException($"Sample '{name}' expectFields has a duplicate path.");
            }

            JsonElement value = field.Value;
            PackFieldExpectation expectation = value.ValueKind switch
            {
                JsonValueKind.String when value.GetString() is PackFieldExpectation.Present or PackFieldExpectation.Absent =>
                    new(field.Name, segments, value.GetString()!, null),
                JsonValueKind.String or JsonValueKind.True or JsonValueKind.False =>
                    new(field.Name, segments, PackFieldExpectation.Exact, value.Clone()),
                JsonValueKind.Number when value.TryGetDouble(out double number) && double.IsFinite(number) =>
                    new(field.Name, segments, PackFieldExpectation.Exact, value.Clone()),
                _ => throw new InvalidDataException(
                    $"Sample '{name}' expectFields '{field.Name}' must be a string, finite number or boolean.")
            };
            expectations.Add(expectation);
        }

        if (expectations.Count is 0 or > MaximumExpectations)
        {
            throw new InvalidDataException($"Sample '{name}' expectFields must have 1 to {MaximumExpectations} paths.");
        }

        return expectations;
    }

    /// <summary>
    /// Checks expectations against the redacted event. <paramref name="inputs"/> are the
    /// pre-redaction documents (the sample's raw record or event, and the mapped envelope);
    /// they are only used to recognise withheld values and are never echoed.
    /// </summary>
    public static IReadOnlyList<string> Check(
        IReadOnlyList<PackFieldExpectation> expectations,
        string redactedJson,
        IEnumerable<string> inputs,
        IReadOnlyList<string> forbidden)
    {
        using JsonDocument output = JsonDocument.Parse(redactedJson, new JsonDocumentOptions { MaxDepth = 64 });
        HashSet<string> released = new(StringComparer.Ordinal);
        CollectStrings(output.RootElement, released);
        HashSet<string> withheld = new(StringComparer.Ordinal);
        foreach (string input in inputs)
        {
            using JsonDocument document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 64 });
            HashSet<string> values = new(StringComparer.Ordinal);
            CollectStrings(document.RootElement, values);
            withheld.UnionWith(values.Where(value => !released.Contains(value)));
        }

        List<string> problems = [];
        foreach (PackFieldExpectation expectation in expectations)
        {
            JsonElement? actual = Resolve(output.RootElement, expectation.Segments);
            string path = expectation.Path;
            if (expectation.Kind == PackFieldExpectation.Present)
            {
                if (actual is null)
                {
                    problems.Add($"Field '{path}': expected present, but it is absent.");
                }

                continue;
            }

            if (expectation.Kind == PackFieldExpectation.Absent)
            {
                if (actual is { } value)
                {
                    problems.Add($"Field '{path}': expected absent, got {Describe(value)}.");
                }

                continue;
            }

            JsonElement expected = expectation.Value!.Value;
            if (expected.ValueKind == JsonValueKind.String && expected.GetString() is { } text
                && (withheld.Contains(text) || forbidden.Any(item => text.Contains(item, StringComparison.Ordinal))))
            {
                problems.Add($"Field '{path}': the expected value does not survive redaction; expect only post-redaction values.");
                continue;
            }

            if (actual is not { } found)
            {
                problems.Add($"Field '{path}': expected {Render(expected)}, but it is absent.");
            }
            else if (KindName(found) != KindName(expected))
            {
                problems.Add($"Field '{path}': type mismatch, expected {Describe(expected)}, got {Describe(found)}.");
            }
            else if (!Matches(expected, found))
            {
                problems.Add($"Field '{path}': expected {Render(expected)}, got {Render(found)}.");
            }
        }

        return problems;
    }

    /// <summary>
    /// Follows object members and array indexes. JSON null, and a member name that occurs
    /// more than once (ambiguous), are absent.
    /// </summary>
    private static JsonElement? Resolve(JsonElement root, IReadOnlyList<string> segments)
    {
        JsonElement current = root;
        foreach (string segment in segments)
        {
            JsonElement[] members = current.ValueKind == JsonValueKind.Object
                ? current.EnumerateObject().Where(property => property.Name == segment).Select(property => property.Value).ToArray()
                : [];
            if (members.Length == 1)
            {
                current = members[0];
            }
            else if (current.ValueKind == JsonValueKind.Array && Index().IsMatch(segment)
                && int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int index)
                && index < current.GetArrayLength())
            {
                current = current[index];
            }
            else
            {
                return null;
            }
        }

        return current.ValueKind == JsonValueKind.Null ? null : current;
    }

    private static bool Matches(JsonElement expected, JsonElement actual) => expected.ValueKind switch
    {
        JsonValueKind.String => string.Equals(expected.GetString(), actual.GetString(), StringComparison.Ordinal),
        JsonValueKind.Number => actual.TryGetDouble(out double value) && double.IsFinite(value)
            && expected.GetDouble() == value,
        _ => expected.ValueKind == actual.ValueKind
    };

    private static void CollectStrings(JsonElement element, HashSet<string> values)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                values.Add(element.GetString()!);
                break;
            case JsonValueKind.Object:
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    CollectStrings(property.Value, values);
                }

                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in element.EnumerateArray())
                {
                    CollectStrings(item, values);
                }

                break;
        }
    }

    private static string KindName(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => "string",
        JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        _ => "null"
    };

    private static string Describe(JsonElement element) =>
        element.ValueKind is JsonValueKind.Object or JsonValueKind.Array
            ? KindName(element)
            : $"{KindName(element)} {Render(element)}";

    /// <summary>Scalars as JSON text (strings escaped with the default encoder); containers by kind.</summary>
    private static string Render(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                using (MemoryStream buffer = new())
                {
                    using (Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Encoder = JavaScriptEncoder.Default }))
                    {
                        writer.WriteStringValue(element.GetString());
                    }

                    return Encoding.UTF8.GetString(buffer.ToArray());
                }

            case JsonValueKind.Number:
                return element.GetRawText();
            case JsonValueKind.True:
                return "true";
            case JsonValueKind.False:
                return "false";
            default:
                return KindName(element);
        }
    }

    [GeneratedRegex(@"^[A-Za-z0-9_$@-]{1,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Segment();

    [GeneratedRegex(@"^(?:0|[1-9][0-9]{0,8})\z", RegexOptions.CultureInvariant)]
    private static partial Regex Index();
}
