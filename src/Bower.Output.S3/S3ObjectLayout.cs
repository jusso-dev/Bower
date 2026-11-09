using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;

namespace Bower.Output.S3;

/// <summary>One planned object: its events in queue order, key and uncompressed NDJSON body.</summary>
public sealed record S3PlannedObject(string Key, IReadOnlyList<string> EventIds, byte[] Body);

/// <summary>
/// Deterministic object layout, pinned by
/// <c>tests/fixtures/s3-output/vectors.json</c>. Keys are
/// <c>&lt;prefix&gt;/&lt;collectorId&gt;/yyyy/MM/dd/HH/&lt;object hash&gt;.jsonl[.gz]</c>, partitioned by
/// the first event's queue receive time (UTC). Receive time is set once by the collector and
/// never changes, so a retry of the same batch rewrites the same key; delivery time would
/// move a retry into a later partition and duplicate the object. The collector segment keeps
/// collectors that share a bucket and prefix apart. The object hash binds the exact event
/// ids and the uncompressed body (<see cref="ObjectHash"/>), so an existing key (412) always
/// holds byte-identical content.
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
        string collectorId,
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
                objects.Add(Build(current, prefix, collectorId, currentBytes, gzip));
                current = [];
                currentBytes = 0;
            }

            current.Add(item);
            currentBytes += recordBytes;
        }

        if (current.Count > 0)
        {
            objects.Add(Build(current, prefix, collectorId, currentBytes, gzip));
        }

        return (objects, rejected);
    }

    /// <summary>Object key for these events, in this order, with this uncompressed body.</summary>
    public static string Key(
        string prefix, string collectorId, DateTimeOffset firstReceivedAt, IReadOnlyList<string> eventIds, byte[] body, bool gzip)
    {
        DateTimeOffset utc = firstReceivedAt.ToUniversalTime();
        return string.Create(CultureInfo.InvariantCulture,
            $"{prefix}/{collectorId}/{utc:yyyy}/{utc:MM}/{utc:dd}/{utc:HH}/{ObjectHash(eventIds, body)}{(gzip ? ".jsonl.gz" : ".jsonl")}");
    }

    /// <summary>
    /// Lowercase hex SHA-256 of an unambiguous encoding: the id count, then each UTF-8 id
    /// prefixed with its byte length (all 32-bit big-endian), then the 32-byte SHA-256 of the
    /// uncompressed NDJSON body. Gzip bytes differ between runtimes; the body does not.
    /// </summary>
    public static string ObjectHash(IReadOnlyList<string> eventIds, byte[] body)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)eventIds.Count);
        hash.AppendData(length);
        foreach (string eventId in eventIds)
        {
            byte[] id = Encoding.UTF8.GetBytes(eventId);
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)id.Length);
            hash.AppendData(length);
            hash.AppendData(id);
        }

        hash.AppendData(SHA256.HashData(body));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static S3PlannedObject Build(List<QueuedEvent> events, string prefix, string collectorId, long bytes, bool gzip)
    {
        byte[] body = new byte[bytes];
        int offset = 0;
        foreach (QueuedEvent item in events)
        {
            offset += Encoding.UTF8.GetBytes(item.Payload, body.AsSpan(offset));
            body[offset++] = (byte)'\n';
        }

        string[] ids = [.. events.Select(item => item.EventId)];
        return new S3PlannedObject(Key(prefix, collectorId, events[0].ReceivedAt, ids, body, gzip), ids, body);
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
