using System.Text.Json;

namespace Bower.Source.WindowsEventLog;

/// <summary>
/// Durable position in one channel, stored in the queue database's source cursor table.
/// Every event up to and including <see cref="RecordId"/> is durably queued or
/// definitively dropped. The Windows query asks only for later records.
/// </summary>
public sealed record WindowsEventBookmark(int SchemaVersion, string Channel, long RecordId)
{
    public const int CurrentSchemaVersion = 1;

    public static WindowsEventBookmark At(string channel, long recordId) => new(CurrentSchemaVersion, channel, recordId);

    public string Serialize() => JsonSerializer.Serialize(this, WindowsEventLogJsonContext.Default.WindowsEventBookmark);

    /// <summary>Fails closed: a bookmark that is not ours, or for another channel, is never reinterpreted.</summary>
    public static WindowsEventBookmark Deserialize(string value, string channel)
    {
        WindowsEventBookmark? bookmark;
        try
        {
            bookmark = JsonSerializer.Deserialize(value, WindowsEventLogJsonContext.Default.WindowsEventBookmark);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Windows Event Log bookmark is invalid.", exception);
        }

        if (bookmark is null || bookmark.SchemaVersion != CurrentSchemaVersion || bookmark.RecordId < 0
            || !string.Equals(bookmark.Channel, channel, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Windows Event Log bookmark version or channel does not match the subscription.");
        }

        return bookmark;
    }
}
