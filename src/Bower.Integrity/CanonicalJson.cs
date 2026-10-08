using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bower.Integrity;

/// <summary>
/// Deterministic JSON for signing: object keys sorted ordinally, no insignificant
/// whitespace, numbers and strings as System.Text.Json writes them.
/// </summary>
public static class CanonicalJson
{
    public static byte[] Bytes(JsonNode? node)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = false }))
        {
            Write(writer, node);
        }

        return stream.ToArray();
    }

    public static string Text(JsonNode? node) => Encoding.UTF8.GetString(Bytes(node));

    private static void Write(Utf8JsonWriter writer, JsonNode? node)
    {
        switch (node)
        {
            case null:
                writer.WriteNullValue();
                break;
            case JsonObject obj:
                writer.WriteStartObject();
                foreach (KeyValuePair<string, JsonNode?> property in obj.OrderBy(item => item.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Key);
                    Write(writer, property.Value);
                }

                writer.WriteEndObject();
                break;
            case JsonArray array:
                writer.WriteStartArray();
                foreach (JsonNode? item in array)
                {
                    Write(writer, item);
                }

                writer.WriteEndArray();
                break;
            default:
                node.WriteTo(writer);
                break;
        }
    }
}
