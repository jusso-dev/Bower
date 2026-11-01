using System.Text;
using System.Text.Json;

namespace Bower.Abstractions;

/// <summary>Compares only the root event ID after redaction, without returning either value.</summary>
public static class RedactedEventIdentity
{
    public const string RetryReason = "event-id-redacted";

    // Match the collector/redactor input limit and Rust identity comparison.
    public const int MaximumDocumentBytes = 1_048_576;

    public enum Comparison { InvalidOriginal, Unchanged, Changed }

    public static Comparison Compare(string original, string redacted)
    {
        if (Encoding.UTF8.GetByteCount(original) > MaximumDocumentBytes)
        {
            return Comparison.InvalidOriginal;
        }
        string? before;
        try
        {
            before = ReadId(original, requireString: true);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return Comparison.InvalidOriginal;
        }
        if (before is null)
        {
            return Comparison.InvalidOriginal;
        }
        if (Encoding.UTF8.GetByteCount(redacted) > MaximumDocumentBytes)
        {
            return Comparison.Changed;
        }
        try
        {
            return string.Equals(before, ReadId(redacted, requireString: false), StringComparison.Ordinal)
                ? Comparison.Unchanged : Comparison.Changed;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return Comparison.Changed;
        }
    }

    private static string? ReadId(string json, bool requireString)
    {
        using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
        bool seen = false;
        string? value = null;
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (!property.NameEquals("eventId")) continue;
            if (seen || (requireString && property.Value.ValueKind != JsonValueKind.String)) throw new JsonException();
            seen = true;
            if (property.Value.ValueKind == JsonValueKind.String) value = property.Value.GetString();
        }
        return value;
    }
}
