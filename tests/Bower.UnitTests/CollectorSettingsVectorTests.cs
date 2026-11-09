using System.Text;
using System.Text.Json.Nodes;
using Bower.Collector;

namespace Bower.UnitTests;

/// <summary>
/// Collector settings vectors in tests/fixtures/collector-settings, shared with
/// </summary>
public sealed class CollectorSettingsVectorTests
{
    private static JsonObject Vectors { get; } = (JsonObject)JsonNode.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "collector-settings", "vectors.json")))!;

    public static TheoryData<string> IngestTokenVectors() => Names("ingestTokens");

    public static TheoryData<string> ScopeSourceVectors() => Names("producerScopeSources");

    public static TheoryData<string> HashVectors() => Names("configurationHashes");

    [Theory]
    [MemberData(nameof(IngestTokenVectors))]
    public void IngestTokenReferencesAreRefusedWithoutEchoingThem(string name)
    {
        JsonNode vector = Find("ingestTokens", name);
        string value = vector["value"]!.GetValue<string>();
        using TemporaryDirectory directory = new();
        Dictionary<string, string> environment = Environment(Vectors["environment"]);
        if (vector["source"]!.GetValue<string>() == "file")
        {
            string path = Path.Combine(directory.Path, "ingest-token");
            File.WriteAllText(path, value, new UTF8Encoding(false));
            environment["BOWER_INGEST_TOKEN_FILE"] = path;
        }
        else
        {
            environment["BOWER_INGEST_TOKEN"] = value;
        }

        // FromEnvironment validates, so a refused token never yields settings.
        if (vector["accepted"]!.GetValue<bool>())
        {
            CollectorSettings settings = CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key));
            Assert.Equal(value.Trim(), settings.IngestToken);
            return;
        }

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key)));
        Assert.Equal(Vectors["referenceRefusal"]!.GetValue<string>(), error.Message);
        Assert.DoesNotContain("example", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [MemberData(nameof(ScopeSourceVectors))]
    public void ProducerScopeSourcesArePinned(string name)
    {
        JsonNode vector = Find("producerScopeSources", name);
        Dictionary<string, string> environment = Environment(vector["environment"]);
        environment.TryAdd("BOWER_COLLECTOR_ID", "collector-test");

        if (!vector["valid"]!.GetValue<bool>())
        {
            Assert.Throws<InvalidOperationException>(
                () => CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key)));
            return;
        }

        CollectorSettings settings = CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key));
        Assert.Equal(vector["inlineScopes"]?.GetValue<string>(), settings.ProducerScopesJson);
        Assert.Equal(vector["scopesFile"]?.GetValue<string>(), settings.ProducerScopesFile);
    }

    [Theory]
    [MemberData(nameof(HashVectors))]
    public void ConfigurationHashesMatchVectors(string name)
    {
        JsonNode vector = Find("configurationHashes", name);
        Dictionary<string, string> environment = Environment(vector["environment"]);
        CollectorSettings settings = CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key));
        Assert.Equal(vector["expected"]!.GetValue<string>(), settings.ConfigurationHash());
    }

    private static TheoryData<string> Names(string group) =>
        [.. Vectors[group]!.AsArray().Select(item => item!["name"]!.GetValue<string>())];

    private static JsonNode Find(string group, string name) =>
        Vectors[group]!.AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!;

    private static Dictionary<string, string> Environment(JsonNode? values) =>
        values!.AsObject().ToDictionary(item => item.Key, item => item.Value!.GetValue<string>());
}
