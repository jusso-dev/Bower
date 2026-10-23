using System.Text;
using System.Text.Json;

namespace Bower.Persistence;

internal static class ReplayContent
{
    internal static bool Equivalent(string left, string right) =>
        string.Equals(Normalize(left), Normalize(right), StringComparison.Ordinal);

    private static string Normalize(string payload)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement root = document.RootElement;
            bool envelope = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("schemaVersion", out _)
                && root.TryGetProperty("eventType", out _);
            bool original = envelope && root.TryGetProperty("eventOriginalId", out JsonElement id)
                && id.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(id.GetString());
            using MemoryStream stream = new();
            using (Utf8JsonWriter writer = new(stream))
            {
                Write(writer, root, envelope, original);
            }
            return Encoding.UTF8.GetString(stream.ToArray());
        }
        catch (JsonException)
        {
            return payload;
        }
    }

    private static void Write(Utf8JsonWriter writer, JsonElement value, bool envelope = false, bool original = false)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (JsonProperty property in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
            {
                // Exclude only collector decoration, never unknown source fields.
                if (envelope && (property.Name is "collector" or "security" or "timeObserved"
                    || (original && property.Name == "eventId")))
                {
                    continue;
                }
                writer.WritePropertyName(property.Name);
                Write(writer, property.Value);
            }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (JsonElement child in value.EnumerateArray())
            {
                Write(writer, child);
            }
            writer.WriteEndArray();
        }
        else
        {
            value.WriteTo(writer);
        }
    }
}
