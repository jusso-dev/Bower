using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Source.MicrosoftCloud;

/// <summary>
/// Builds the flat JSON record a signed pack parser reads (<c>PackRuntime</c>): string values
/// only, bounded lengths, <c>id</c> first so the collector recognises the Bower-computed id.
/// The record lives in memory for one submission; it is never logged or persisted, and only
/// the fields the pack parser maps can reach the envelope, after redaction.
/// </summary>
internal sealed class MicrosoftCloudRecord(MicrosoftCloudInputOptions input)
{
    /// <summary>Longest value written; a pack parser refuses longer mapped values.</summary>
    public const int MaximumValueLength = 1_024;

    private readonly List<KeyValuePair<string, string>> fields = [];

    public MicrosoftCloudRecord Add(string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            fields.Add(new KeyValuePair<string, string>(name, Clip(value.Trim(), MaximumValueLength)));
        }

        return this;
    }

    /// <summary>
    /// The record with its event id: <c>mscloud-</c> and 32 hex characters of SHA-256 over the
    /// input, the source record id and the record content. Re-reading an unchanged record (window
    /// overlap, a re-read page after a crash) gives the same id, so the queue deduplicates it; a
    /// record whose content changed is a new event rather than an identity conflict.
    /// </summary>
    public string Build(string sourceRecordId)
    {
        string content = Write(null);
        string material = string.Join(
            '\u001f',
            "bower-mscloud-v1",
            input.Id,
            input.SourceKind,
            input.TenantId,
            sourceRecordId,
            content);
        string id = "mscloud-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)))[..32];
        return Write(id);
    }

    private string Write(string? id)
    {
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            if (id is not null)
            {
                writer.WriteString("id", id);
            }

            writer.WriteString("input", input.Id);
            writer.WriteString("sourceKind", input.SourceKind);
            writer.WriteString("tenantId", input.TenantId);
            foreach (KeyValuePair<string, string> field in fields)
            {
                writer.WriteString(field.Key, field.Value);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    public static string? String(JsonElement item, string name) =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out JsonElement value)
            ? value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number => value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            }
            : null;

    public static JsonElement Object(JsonElement item, string name) =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.Object
            ? value
            : default;

    public static IEnumerable<JsonElement> Array(JsonElement item, string name) =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
            : [];

    /// <summary>Canonical UTC text, or null for a missing or unparseable time.</summary>
    public static string? Time(string? value) =>
        value is not null && DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? MicrosoftCloudSourceConfigurationLoader.Format(parsed)
            : null;

    /// <summary>Comma-joined distinct values, cut at a whole value so the result never exceeds the cap (envelope labels hold 256 characters).</summary>
    public static string? Join(IEnumerable<string?> values, int maximumLength = 256)
    {
        StringBuilder builder = new();
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (string? value in values)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Contains(',') || !seen.Add(value))
            {
                continue;
            }

            int length = builder.Length + (builder.Length == 0 ? 0 : 1) + value.Length;
            if (length > maximumLength)
            {
                break;
            }

            builder.Append(builder.Length == 0 ? string.Empty : ",").Append(value);
        }

        return builder.Length == 0 ? null : builder.ToString();
    }

    internal static string Clip(string value, int maximumLength)
    {
        if (value.Length <= maximumLength)
        {
            return value;
        }

        int end = maximumLength;
        if (char.IsHighSurrogate(value[end - 1]))
        {
            end--;
        }

        return value[..end];
    }
}
