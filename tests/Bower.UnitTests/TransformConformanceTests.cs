using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;

namespace Bower.UnitTests;

/// <summary>
/// Transform language conformance vectors shared with the Rust port
/// (<c>rust/crates/bower-pipeline/tests/fixtures/transform-vectors.json</c>): validation issues,
/// canonical output bytes, step counts and runtime error codes must match exactly. Inputs are
/// hand-written; set <c>BOWER_TRANSFORM_VECTOR_OUTPUT</c> to a file path to regenerate the
/// expectations after an intended change, then review the diff.
/// </summary>
public sealed class TransformConformanceTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "pipeline-vectors", "transform-vectors.json");

    [Fact]
    public void TransformVectors_MatchCSharpOutcomes()
    {
        JsonObject fixture = JsonNode.Parse(File.ReadAllText(FixturePath))!.AsObject();
        DateTimeOffset defaultTime = DateTimeOffset.Parse(
            fixture["defaultEvaluationTime"]!.GetValue<string>(), CultureInfo.InvariantCulture);
        JsonArray cases = [];
        foreach (JsonNode? node in fixture["cases"]!.AsArray())
        {
            JsonObject source = node!.AsObject();
            JsonObject result = [];
            foreach (string key in new[] { "name", "fields", "tables", "statements", "evaluationTime", "input" })
            {
                if (source[key] is { } value)
                {
                    result[key] = value.DeepClone();
                }
            }

            TransformDefinition definition = Definition(source);
            IReadOnlyList<TransformIssue> issues = TransformProgram.Validate(definition);
            result["issues"] = new JsonArray([.. issues.Select(issue => (JsonNode?)issue.ToString())]);
            if (issues.Count == 0 && source["input"]?.GetValue<string>() is { } input)
            {
                DateTimeOffset time = source["evaluationTime"] is { } text
                    ? DateTimeOffset.Parse(text.GetValue<string>(), CultureInfo.InvariantCulture)
                    : defaultTime;
                TransformProgram program = TransformProgram.Compile(definition);
                try
                {
                    TransformOutput output = program.Execute(input, time);
                    Assert.Equal(output, program.Execute(input, time));
                    result["output"] = output.RecordJson;
                    result["steps"] = output.Steps;
                }
                catch (TransformException exception)
                {
                    result["error"] = exception.Code;
                }
            }

            cases.Add(result);
        }

        JsonObject actual = new()
        {
            ["_comment"] = fixture["_comment"]!.DeepClone(),
            ["defaultEvaluationTime"] = fixture["defaultEvaluationTime"]!.DeepClone(),
            ["cases"] = cases
        };
        string generated = actual.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }) + "\n";
        if (Environment.GetEnvironmentVariable("BOWER_TRANSFORM_VECTOR_OUTPUT") is { Length: > 0 } outputPath)
        {
            File.WriteAllText(outputPath, generated);
        }

        Assert.Equal(File.ReadAllText(FixturePath), generated);
    }

    /// <summary>
    /// Malformed and adversarial statements from a fixed linear congruential generator:
    /// grammar-shaped statements, some with a random fragment spliced in, and fragment soup.
    /// Validation must never throw, execution may only fail with a transform code, and the
    /// FNV-1a digest of every outcome must equal the Rust port's (<c>transform_vectors.rs</c>).
    /// </summary>
    [Fact]
    public void DeterministicFuzz_NeverThrowsAndMatchesRust()
    {
        CustomLogField[] fields = [new("user", CustomLogValueType.Text, null, null, true)];
        Dictionary<string, IReadOnlyDictionary<string, string>> tables = new()
        {
            ["t"] = new Dictionary<string, string> { ["Admin"] = "x" }
        };
        const string input = """{"a":"Alpha,beta","b":"12","user":"Admin","m":{"x":"y"}}""";
        DateTimeOffset at = new(2026, 10, 26, 1, 2, 3, TimeSpan.Zero);
        FuzzGenerator generator = new(87);
        ulong digest = 14695981039346656037;
        int valid = 0;
        for (int index = 0; index < 4000; index++)
        {
            TransformDefinition definition = new([generator.Statement()], tables, fields);
            IReadOnlyList<TransformIssue> issues = TransformProgram.Validate(definition);
            string outcome = string.Join(" ", issues);
            if (issues.Count == 0)
            {
                valid++;
                try
                {
                    TransformOutput output = TransformProgram.Compile(definition).Execute(input, at);
                    outcome = $"{output.RecordJson}|{output.Steps}";
                }
                catch (TransformException exception)
                {
                    outcome = exception.Code;
                }
            }

            foreach (byte value in Encoding.UTF8.GetBytes(outcome + "\n"))
            {
                digest = (digest ^ value) * 1099511628211;
            }
        }

        Assert.Equal(FuzzValidCount, valid);
        Assert.Equal(FuzzDigest, digest);
    }

    private const int FuzzValidCount = 1287;
    private const ulong FuzzDigest = 4304864850446909586;

    /// <summary>Same generator as <c>FuzzGenerator</c> in the Rust port; keep the call order identical.</summary>
    private sealed class FuzzGenerator(ulong seed)
    {
        private static readonly string[] Fragments =
        [
            ".a", ".b", ".user", " = ", "lower(", ")", "(", ",", "\"x\"", "'[a-z]+'", "if ", " { ", " }", " else ",
            "&&", "||", "!", "==", "<", "del(", ";", "'(?<g>a*)*'", ".\"q.r\"", " ", "\"", "'", "\\", ".", "-", "{"
        ];

        private static readonly string[] Paths = [".a", ".b", ".m", ".m.x", ".missing", ".\"q.r\"", ".user"];

        private static readonly string[] Literals =
        [
            "\"x\"", "1", "-1", "null", "true", "\",\"", "'[a-z]+'", "'(?<g>a*)*'", "\"rfc3339\"", "\"t\"", "'^(?<w>\\w+)'"
        ];

        private static readonly string[] Functions =
        [
            "lower", "upper", "trim", "replace", "split", "join", "at", "concat", "contains", "coalesce", "lookup",
            "regex_match", "regex_extract", "parse_timestamp", "to_string", "to_int", "to_bool", "now", "starts_with", "exec"
        ];

        private static readonly string[] Operators = [" == ", " != ", " && ", " || ", " < "];

        private static readonly string[] Targets = [".a", ".b", ".out", ".user", ".m"];

        private ulong state = seed;

        private int Pick(int count)
        {
            state = (state * 6364136223846793005) + 1442695040888963407;
            return (int)((state >> 33) % (ulong)count);
        }

        public string Statement()
        {
            if (Pick(4) == 0)
            {
                StringBuilder soup = new();
                int count = 1 + Pick(12);
                for (int index = 0; index < count; index++)
                {
                    soup.Append(Fragments[Pick(Fragments.Length)]);
                }

                return soup.ToString();
            }

            string statement = Statement(0);
            if (Pick(3) == 0)
            {
                int position = Pick(statement.Length + 1);
                statement = statement.Insert(position, Fragments[Pick(Fragments.Length)]);
            }

            return statement;
        }

        private string Statement(int depth)
        {
            switch (Pick(depth >= 2 ? 3 : 4))
            {
                case 0:
                case 1:
                    {
                        string target = Targets[Pick(Targets.Length)];
                        return target + " = " + Expression(0);
                    }
                case 2:
                    if (Pick(2) == 0)
                    {
                        return "del(" + Targets[Pick(Targets.Length)] + ")";
                    }

                    string from = Targets[Pick(Targets.Length)];
                    return "rename(" + from + ", " + Targets[Pick(Targets.Length)] + ")";
                default:
                    {
                        string condition = Expression(1);
                        string then = Statement(depth + 1);
                        return Pick(2) == 0
                            ? "if " + condition + " { " + then + " }"
                            : "if " + condition + " { " + then + " } else { " + Statement(depth + 1) + " }";
                    }
            }
        }

        private string Expression(int depth)
        {
            switch (Pick(depth >= 3 ? 2 : 4))
            {
                case 0:
                    return Paths[Pick(Paths.Length)];
                case 1:
                    return Literals[Pick(Literals.Length)];
                case 2:
                    {
                        string name = Functions[Pick(Functions.Length)];
                        int count = Pick(4);
                        List<string> arguments = [];
                        for (int index = 0; index < count; index++)
                        {
                            arguments.Add(Expression(depth + 1));
                        }

                        return name + "(" + string.Join(", ", arguments) + ")";
                    }
                default:
                    {
                        string left = Expression(depth + 1);
                        string op = Operators[Pick(Operators.Length)];
                        return left + op + Expression(depth + 1);
                    }
            }
        }
    }

    internal static TransformDefinition Definition(JsonObject source)
    {
        List<CustomLogField> fields = [];
        foreach (JsonNode? field in source["fields"]?.AsArray() ?? [])
        {
            fields.Add(new CustomLogField(
                field!["name"]!.GetValue<string>(), CustomLogValueType.Text, null, null, field["sensitive"]!.GetValue<bool>()));
        }

        Dictionary<string, IReadOnlyDictionary<string, string>>? tables = source["tables"]?.AsObject().ToDictionary(
            table => table.Key,
            table => (IReadOnlyDictionary<string, string>)table.Value!.AsObject()
                .ToDictionary(entry => entry.Key, entry => entry.Value!.GetValue<string>(), StringComparer.Ordinal),
            StringComparer.Ordinal);
        string?[] statements = [.. source["statements"]!.AsArray().Select(item => item?.GetValue<string>())];
        return new TransformDefinition(statements, tables, fields);
    }
}
