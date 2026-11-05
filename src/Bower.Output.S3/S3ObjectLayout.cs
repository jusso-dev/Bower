using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;

namespace Bower.Output.S3;

/// <summary>One planned object: its events in queue order, key and uncompressed NDJSON body.</summary>
public sealed record S3PlannedObject(string Key, IReadOnlyList<string> EventIds, byte[] Body);

/// <summary>
/// Deterministic object layout, shared with the Rust port and pinned by
/// <c>tests/fixtures/s3-output/vectors.json</c>. Keys are
/// <c>&lt;prefix&gt;/yyyy/MM/dd/HH/&lt;sha256 of ordered event ids&gt;.jsonl[.gz]</c>, partitioned by the
/// first event's queue receive time (UTC). Receive time is set once by the collector and
/// never changes, so a retry of the same batch rewrites the same key; delivery time would
/// move a retry into a later partition and duplicate the object.
/// </summary>
public static class S3ObjectLayout
{
    public const string InvalidJsonCode = "payload-invalid-json";
    public const string TooLargeCode = "payload-too-large";

    /// <summary>
    /// Splits events, in order, into objects under the byte and count caps. A payload that
    /// can never be written (invalid JSON, a line break, larger than one object) fails alone
    /// and permanently.
    /// </summary>
    public static (IReadOnlyList<S3PlannedObject> Objects, IReadOnlyList<DeliveryFailure> Rejected) Plan(
        IReadOnlyList<QueuedEvent> events,
        string prefix,
        int maximumObjectBytes,
        int maximumObjectEvents,
        bool gzip)
    {
        ArgumentNullException.ThrowIfNull(events);
        List<S3PlannedObject> objects = [];
        List<DeliveryFailure> rejected = [];
        List<QueuedEvent> current = [];
        long currentBytes = 0;
        foreach (QueuedEvent item in events)
        {
            if (!IsSingleLineJson(item.Payload))
            {
                rejected.Add(new DeliveryFailure(item.EventId, InvalidJsonCode, false, null));
                continue;
            }

            long recordBytes = Encoding.UTF8.GetByteCount(item.Payload) + 1L;
            if (recordBytes > maximumObjectBytes)
            {
                rejected.Add(new DeliveryFailure(item.EventId, TooLargeCode, false, null));
                continue;
            }

            if (current.Count > 0 && (currentBytes + recordBytes > maximumObjectBytes || current.Count >= maximumObjectEvents))
            {
                objects.Add(Build(current, prefix, currentBytes, gzip));
                current = [];
                currentBytes = 0;
            }

            current.Add(item);
            currentBytes += recordBytes;
        }

        if (current.Count > 0)
        {
            objects.Add(Build(current, prefix, currentBytes, gzip));
        }

        return (objects, rejected);
    }

    /// <summary>Object key for events in this order whose first event was received at <paramref name="firstReceivedAt"/>.</summary>
    public static string Key(string prefix, DateTimeOffset firstReceivedAt, IReadOnlyList<string> eventIds, bool gzip)
    {
        DateTimeOffset utc = firstReceivedAt.ToUniversalTime();
        return string.Create(CultureInfo.InvariantCulture,
            $"{prefix}/{utc:yyyy}/{utc:MM}/{utc:dd}/{utc:HH}/{EventIdsHash(eventIds)}{(gzip ? ".jsonl.gz" : ".jsonl")}");
    }

    /// <summary>Lowercase hex SHA-256 of the UTF-8 event ids joined by line feeds.</summary>
    public static string EventIdsHash(IReadOnlyList<string> eventIds) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', eventIds))));

    private static S3PlannedObject Build(List<QueuedEvent> events, string prefix, long bytes, bool gzip)
    {
        byte[] body = new byte[bytes];
        int offset = 0;
        foreach (QueuedEvent item in events)
        {
            offset += Encoding.UTF8.GetBytes(item.Payload, body.AsSpan(offset));
            body[offset++] = (byte)'\n';
        }

        string[] ids = [.. events.Select(item => item.EventId)];
        return new S3PlannedObject(Key(prefix, events[0].ReceivedAt, ids, gzip), ids, body);
    }

    /// <summary>One JSON value with no raw line break, so it is exactly one NDJSON line.</summary>
    private static bool IsSingleLineJson(string payload)
    {
        if (payload.AsSpan().IndexOfAny('\n', '\r') >= 0)
        {
            return false;
        }

        try
        {
            Utf8JsonReader reader = new(Encoding.UTF8.GetBytes(payload), new JsonReaderOptions { MaxDepth = 64 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            reader.Skip();
            return !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
