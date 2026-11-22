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

    /// <param name="maximumLength">
    /// The envelope limit of the field this value maps to (for example 128 for an action or
    /// target type, 256 for labels and identities), so a long value is clipped here rather
    /// than refused by the pack parser.
    /// </param>
    public MicrosoftCloudRecord Add(string name, string? value, int maximumLength = MaximumValueLength)
    {
        if (!string.IsNullOrWhiteSpace(value) && budget > 0)
        {
            string clipped = Clip(value.Trim(), Math.Min(Math.Min(maximumLength, MaximumValueLength), budget / 6));
            if (clipped.Length > 0)
            {
                budget -= clipped.Length * 6;
                fields.Add(new KeyValuePair<string, string>(name, clipped));
            }
        }

        return this;
    }

    /// <summary>
    /// An IP address in canonical form, or null. Strips an IPv4 <c>:port</c> and brackets, so
    /// an unusual address never makes the pack parser refuse the whole event.
    /// </summary>
    public static string? Address(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
        {
            return null;
        }

        string text = value.Trim();
        if (text.StartsWith('['))
        {
            // [IPv6] or [IPv6]:port.
            int close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 0 || (close != text.Length - 1 && !IsPort(text.AsSpan(close + 1))))
            {
                return null;
            }

            text = text[1..close];
        }
        else if (text.Count(character => character == ':') == 1)
        {
            // IPv4:port. A bare IPv6 address always has two or more colons.
            int colon = text.IndexOf(':', StringComparison.Ordinal);
            if (!IsPort(text.AsSpan(colon)))
            {
                return null;
            }

            text = text[..colon];
        }

        if (text.Contains('%', StringComparison.Ordinal)
            || !System.Net.IPAddress.TryParse(text, out System.Net.IPAddress? address))
        {
            return null;
        }

        string canonical = address.ToString();
        // IPv4 must already be in canonical dotted form (no leading zeros, no short forms),
        // which is exactly what the pack runtime accepts.
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && canonical != text
            ? null
            : canonical;

        static bool IsPort(ReadOnlySpan<char> suffix) =>
            suffix.Length is >= 2 and <= 6 && suffix[0] == ':'
            && int.TryParse(suffix[1..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int port)
            && port is >= 1 and <= 65_535;
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

    /// <summary>
    /// Escaped bytes all values of one record may use. JSON escaping is at most 6 bytes per
    /// UTF-16 unit, so values are clipped against this budget as they are added and a record
    /// always stays below the pack parser's 32 KiB limit. Clipping depends only on the input,
    /// so a re-read gives the same record and the same event id.
    /// </summary>
    public const int MaximumValueBytes = 28_672;

    private int budget = MaximumValueBytes;

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

        if (maximumLength <= 0)
        {
            return string.Empty;
        }

        int end = maximumLength;
        if (char.IsHighSurrogate(value[end - 1]))
        {
            end--;
        }

        return value[..end];
    }
}
