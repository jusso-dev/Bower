using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Source.WindowsEventLog;

/// <summary>
/// Turns a parsed event into the flat JSON record a signed pack parser reads
/// (<c>PackRuntime</c>): string values only, at most 64 fields. The record lives in memory
/// for one submission; it is never logged or persisted, and only the fields the pack
/// parser maps can reach the envelope, after redaction.
/// </summary>
public static class WindowsEventRecord
{
    public const int MaximumFields = 64;

    /// <summary>A pack parser cannot read longer values, so they are left out of the record.</summary>
    public const int MaximumValueLength = 2048;

    public static string Build(WindowsEvent windowsEvent, string subscriptionId, string? message)
    {
        ArgumentNullException.ThrowIfNull(windowsEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(subscriptionId);
        string created = Format(windowsEvent.TimeCreated);
        List<KeyValuePair<string, string>> fields =
        [
            new("id", EventId(windowsEvent.Channel, windowsEvent.Computer, windowsEvent.RecordId, created)),
            new("subscription", subscriptionId),
            new("channel", windowsEvent.Channel),
            new("provider", windowsEvent.Provider),
            new("eventId", windowsEvent.EventId.ToString(CultureInfo.InvariantCulture)),
            new("recordId", windowsEvent.RecordId.ToString(CultureInfo.InvariantCulture)),
            new("computer", windowsEvent.Computer),
            new("timeCreated", created)
        ];
        fields.AddRange(windowsEvent.Header);
        HashSet<string> names = new(fields.Select(field => field.Key), StringComparer.Ordinal);
        if (message is { Length: > 0 and <= MaximumValueLength })
        {
            fields.Add(new("message", message));
            names.Add("message");
        }

        foreach (KeyValuePair<string, string> item in windowsEvent.Data)
        {
            // Pack parsers address fields by name: unreadable names, over-long values and
            // repeated names (first wins) are left out rather than guessed at.
            if (IsFieldName(item.Key) && item.Value.Length <= MaximumValueLength && names.Add(item.Key))
            {
                fields.Add(item);
            }
        }

        if (fields.Count > MaximumFields)
        {
            throw new WindowsEventFormatException(WindowsEventFailures.RecordTooLarge);
        }

        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            foreach (KeyValuePair<string, string> field in fields)
            {
                writer.WriteString(field.Key, field.Value);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// <c>winevt-</c> + 32 hex characters of SHA-256 over channel, computer, record id and
    /// creation time, so re-reading an event after a restart deduplicates. The creation
    /// time keeps ids distinct when a cleared or recreated log reuses record ids.
    /// </summary>
    internal static string EventId(string channel, string computer, long recordId, string timeCreated)
    {
        string material = string.Join(
            '\u001f',
            channel,
            computer,
            recordId.ToString(CultureInfo.InvariantCulture),
            timeCreated);
        return "winevt-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)))[..32];
    }

    /// <summary>UTC, microsecond precision (truncated), the same text the syslog source writes.</summary>
    internal static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'ffffff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Same rule as pack parser source field names.</summary>
    private static bool IsFieldName(string value) =>
        value.Length is > 0 and <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.' or '@');
}
