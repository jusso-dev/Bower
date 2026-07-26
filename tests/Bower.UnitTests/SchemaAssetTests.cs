using System.Text.Json;

namespace Bower.UnitTests;

public sealed class SchemaAssetTests
{
    [Fact]
    public void JsonSchemas_AreSyntacticallyValidAndVersioned()
    {
        string root = Path.Combine(AppContext.BaseDirectory, "schemas");
        string[] paths = Directory.GetFiles(root, "*.json", SearchOption.AllDirectories);

        Assert.NotEmpty(paths);
        foreach (string path in paths)
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
            JsonElement schema = document.RootElement;
            Assert.Equal(JsonValueKind.Object, schema.ValueKind);
            Assert.True(schema.TryGetProperty("$schema", out _), path);
            Assert.True(schema.TryGetProperty("$id", out _), path);
        }
    }
}
