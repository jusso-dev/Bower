using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.PolicyEngine;

namespace Bower.UnitTests;

/// <summary>
/// Pins the C# outcomes the Rust port (<c>rust/crates/bower-policy</c>) is tested against, so
/// the shared vectors cannot drift from the specification. Set
/// <c>BOWER_POLICY_VECTOR_OUTPUT</c> to a directory to write the actual outcomes there when
/// regenerating them after an intended behaviour change.
/// </summary>
public sealed class PolicyParityVectorTests
{
    private static readonly string VectorDirectory =
        Path.Combine(AppContext.BaseDirectory, "policy-vectors");

    [Fact]
    public void LoaderVectors_MatchCSharpOutcomes()
    {
        using JsonDocument vectors = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(VectorDirectory, "loader-vectors.json")));
        using TemporaryDirectory directory = new();
        List<(string Name, string Outcome)> actual = [];
        List<string> mismatches = [];

        foreach (JsonElement vector in vectors.RootElement.EnumerateArray())
        {
            string name = vector.GetProperty("name").GetString()!;
            string path = Path.Combine(directory.Path, name);
            File.WriteAllText(path, vector.GetProperty("yaml").GetString()!);
            string outcome;
            try
            {
                outcome = $"OK {PolicyLoader.LoadFile(path).Hash}";
            }
            catch (Exception exception)
            {
                outcome = $"ERR {exception.Message}";
            }

            actual.Add((name, outcome));
            string expected = vector.GetProperty("csharp").GetString()!;
            if (!string.Equals(expected, outcome, StringComparison.Ordinal))
            {
                mismatches.Add($"{name}: expected '{expected}', actual '{outcome}'");
            }
        }

        WriteOutcomes("loader-outcomes.json", actual);
        Assert.True(actual.Count > 200);
        Assert.Empty(mismatches);
    }

    [Fact]
    public void EvaluatorCorpus_MatchesCSharpDecisions()
    {
        List<LoadedPolicy> policies =
        [
            .. PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "policies", "default")),
            .. PolicyLoader.LoadDirectory(Path.Combine(VectorDirectory, "eval", "policies"))
        ];
        DeterministicPolicyEvaluator evaluator = new(policies);
        string[] events = File.ReadAllLines(Path.Combine(VectorDirectory, "eval", "events.jsonl"))
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToArray();
        string[] expected = File.ReadAllLines(Path.Combine(VectorDirectory, "eval", "expected.tsv"));

        List<(string Name, string Outcome)> actual = [];
        for (int index = 0; index < events.Length; index++)
        {
            SecurityEventEnvelope envelope = JsonSerializer.Deserialize(events[index], BowerJson.Envelope)!;
            PolicyDecision decision = evaluator.Evaluate(envelope);
            actual.Add((index.ToString(System.Globalization.CultureInfo.InvariantCulture), string.Join(
                '\t',
                decision.Action,
                decision.PolicyId,
                decision.PolicyVersion,
                decision.PolicyHash,
                decision.Score,
                string.Join('|', decision.Reasons),
                string.Join('|', decision.Warnings))));
        }

        WriteOutcomes("evaluator-outcomes.json", actual);
        Assert.True(events.Length >= 30);
        Assert.Equal(expected, actual.Select(item => item.Outcome).ToArray());
    }

    private static void WriteOutcomes(string fileName, List<(string Name, string Outcome)> outcomes)
    {
        string? output = Environment.GetEnvironmentVariable("BOWER_POLICY_VECTOR_OUTPUT");
        if (string.IsNullOrWhiteSpace(output))
        {
            return;
        }

        Directory.CreateDirectory(output);
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            foreach ((string name, string outcome) in outcomes)
            {
                writer.WriteString(name, outcome);
            }

            writer.WriteEndObject();
        }

        File.WriteAllText(Path.Combine(output, fileName), Encoding.UTF8.GetString(stream.ToArray()));
    }
}
