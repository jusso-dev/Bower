using System.Text;
using System.Text.Json;

namespace Bower.DevSinks;

/// <summary>
/// Bounded in-memory record of what the local stand-in destinations received. Development
/// only: holds the newest <see cref="Capacity"/> records per sink and nothing on disk.
/// </summary>
public sealed class DevSinkStore
{
    public const int Capacity = 500;

    /// <summary>Largest single record kept; longer records are counted but not stored.</summary>
    public const int MaximumRecordBytes = 64 * 1024;

    private readonly Lock gate = new();
    private readonly Dictionary<string, LinkedList<DevSinkRecord>> records = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> counts = new(StringComparer.Ordinal);

    public void Add(string sink, string? eventId, string body)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sink);
        ArgumentNullException.ThrowIfNull(body);
        lock (gate)
        {
            counts[sink] = counts.GetValueOrDefault(sink) + 1;
            if (Encoding.UTF8.GetByteCount(body) > MaximumRecordBytes)
            {
                return;
            }

            if (!records.TryGetValue(sink, out LinkedList<DevSinkRecord>? list))
            {
                list = new LinkedList<DevSinkRecord>();
                records[sink] = list;
            }

            list.AddLast(new DevSinkRecord(sink, eventId, DateTimeOffset.UtcNow, body));
            while (list.Count > Capacity)
            {
                list.RemoveFirst();
            }
        }
    }

    public DevSinkSummary Summary()
    {
        lock (gate)
        {
            return new DevSinkSummary(new Dictionary<string, long>(counts, StringComparer.Ordinal));
        }
    }

    public IReadOnlyList<DevSinkRecord> Records(string sink)
    {
        lock (gate)
        {
            return records.TryGetValue(sink, out LinkedList<DevSinkRecord>? list) ? [.. list] : [];
        }
    }

    /// <summary>True when any sink has received a record with this Bower event id.</summary>
    public bool Contains(string eventId)
    {
        lock (gate)
        {
            return records.Values.Any(list => list.Any(record => string.Equals(record.EventId, eventId, StringComparison.Ordinal)));
        }
    }

    /// <summary>The top-level <c>eventId</c> of a Bower envelope, or null when absent or not JSON.</summary>
    public static string? ReadEventId(ReadOnlySpan<byte> json)
    {
        try
        {
            Utf8JsonReader reader = new(json, new JsonReaderOptions { MaxDepth = 64 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool match = reader.ValueTextEquals("eventId"u8);
                if (!reader.Read())
                {
                    return null;
                }

                if (match)
                {
                    return reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
                }

                reader.Skip();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }
}

public sealed record DevSinkRecord(string Sink, string? EventId, DateTimeOffset ReceivedAt, string Body);

public sealed record DevSinkSummary(IReadOnlyDictionary<string, long> Received);
