using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Dcr;

namespace Bower.Output.AzureLogsIngestion;

public sealed class AzureLogsIngestionOutput : IOutputAdapter
{
    private readonly AzureLogsIngestionOptions options;
    private readonly LogsIngestionClient client;

    public AzureLogsIngestionOutput(
        AzureLogsIngestionOptions options,
        TokenCredential credential,
        LogsIngestionClientOptions? clientOptions = null)
    {
        options.Validate();
        this.options = options;
        client = clientOptions is null
            ? new LogsIngestionClient(options.Endpoint, credential)
            : new LogsIngestionClient(options.Endpoint, credential, clientOptions);
    }

    public string Id => options.Id;

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        if (events.Count == 0)
        {
            return new DeliveryResult([], [], null);
        }

        List<PreparedRecord> records = new(events.Count);
        List<DeliveryFailure> failures = [];
        RecordEncoder encoder = new();
        foreach (QueuedEvent item in events)
        {
            if (!encoder.TryEncode(item.Payload, out byte[]? entry, out string? eventId))
            {
                // A payload that cannot be parsed (including a repeated top-level property,
                // which JsonObject cannot hold) will never succeed: dead-letter it alone
                // instead of failing the whole batch.
                failures.Add(new DeliveryFailure(item.EventId, "payload-invalid-json", false, null));
            }
            else if (!string.Equals(eventId, item.EventId, StringComparison.Ordinal))
            {
                failures.Add(new DeliveryFailure(item.EventId, "payload-event-id-mismatch", false, null));
            }
            else if (IngestionPreflight.Check(entry, options.Schema) is { Count: > 0 } issues)
            {
                // Azure would truncate, coerce or drop this row silently; dead-letter it
                // with the reason instead.
                failures.Add(new DeliveryFailure(item.EventId, $"preflight-{issues[0].Code}", false, null));
            }
            else if (entry.Length + 2 > MaximumBatchBytes)
            {
                failures.Add(new DeliveryFailure(item.EventId, "payload-too-large", false, null));
            }
            else
            {
                records.Add(new PreparedRecord(item.EventId, entry));
            }
        }

        if (records.Count == 0)
        {
            return new DeliveryResult([], failures, null);
        }

        // Own every request and its IDs. Never use SDK UploadFailed attribution: the
        // enumerable upload overload may attach another concurrent batch's records.
        List<List<PreparedRecord>> batches = [];
        List<PreparedRecord> current = [];
        int bytes = 2;
        foreach (PreparedRecord record in records)
        {
            if (current.Count > 0 && bytes + record.Utf8Json.Length + 1 > MaximumBatchBytes)
            {
                batches.Add(current);
                current = [];
                bytes = 2;
            }

            bytes += record.Utf8Json.Length + (current.Count == 0 ? 0 : 1);
            current.Add(record);
        }

        if (current.Count > 0) batches.Add(current);
        ConcurrentBag<string> acknowledged = [];
        ConcurrentBag<DeliveryFailure> uploadFailures = [];
        int isolationBudget = 16;
        await Parallel.ForEachAsync(batches, new ParallelOptions
        {
            MaxDegreeOfParallelism = options.MaximumConcurrency,
            CancellationToken = cancellationToken
        }, async (batch, token) => await UploadBatchAsync(batch, token));
        failures.AddRange(uploadFailures);
        HashSet<string> accepted = new(acknowledged, StringComparer.Ordinal);
        return new DeliveryResult(
            records.Where(record => accepted.Contains(record.EventId)).Select(record => record.EventId).ToArray(),
            failures,
            accepted.Count == 0 ? null : "azure-logs-ingestion:accepted:owned-batches");

        async Task UploadBatchAsync(List<PreparedRecord> batch, CancellationToken token)
        {
            using MemoryStream body = new();
            body.WriteByte((byte)'[');
            for (int index = 0; index < batch.Count; index++)
            {
                if (index > 0) body.WriteByte((byte)',');
                body.Write(batch[index].Utf8Json.Span);
            }
            body.WriteByte((byte)']');
            using RequestContent content = RequestContent.Create(body.ToArray());
            int status;
            DateTimeOffset? retryAfter = null;
            try
            {
                // Protocol overload sends exactly one owned request (AOT safe). NoThrow
                // preserves terminal response headers without exposing service bodies.
                using Response response = await client.UploadAsync(options.DcrImmutableId,
                    options.StreamName, content, context: new RequestContext
                    {
                        CancellationToken = token,
                        ErrorOptions = ErrorOptions.NoThrow
                    });
                status = response.Status;
                retryAfter = ReadRetryAfter(response, DateTimeOffset.UtcNow);
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !token.IsCancellationRequested)
            {
                // Credential/transport exceptions may contain secrets. Never retain text.
                status = 0;
            }

            if (status is >= 200 and < 300)
            {
                foreach (PreparedRecord record in batch) acknowledged.Add(record.EventId);
                return;
            }

            // An ambiguous 400 is not proof of record poison. Bounded bisection lets
            // valid siblings progress; unresolved singletons stay pending for repair.
            if (status == 400 && batch.Count > 1 && (retryAfter is null || retryAfter <= DateTimeOffset.UtcNow)
                && Interlocked.Add(ref isolationBudget, -2) >= 0)
            {
                int middle = batch.Count / 2;
                await UploadBatchAsync(batch.GetRange(0, middle), token);
                await UploadBatchAsync(batch.GetRange(middle, batch.Count - middle), token);
                return;
            }

            foreach (PreparedRecord record in batch)
            {
                uploadFailures.Add(new DeliveryFailure(record.EventId,
                    status == 0 ? "destination-azure-unavailable" : $"destination-azure-http-{status}",
                    true, retryAfter));
            }
        }
    }

    public const int MaximumBatchBytes = 1024 * 1024;

    private static DateTimeOffset? ReadRetryAfter(Response response, DateTimeOffset now)
    {
        foreach (string name in new[] { "retry-after-ms", "x-ms-retry-after-ms", "Retry-After" })
        {
            if (!response.Headers.TryGetValue(name, out string? value)) continue;
            if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double number)
                && double.IsFinite(number) && number >= 0)
            {
                double seconds = name == "Retry-After" ? number : number / 1000;
                return now.AddSeconds(Math.Min(seconds, (DateTimeOffset.MaxValue - now).TotalSeconds - 1));
            }
            if (name == "Retry-After" && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out DateTimeOffset date)) return date;
        }
        return null;
    }
}

public sealed record AzureLogsIngestionOptions
{
    public required string Id { get; init; }

    public required Uri Endpoint { get; init; }

    public required string DcrImmutableId { get; init; }

    public required string StreamName { get; init; }

    public int MaximumConcurrency { get; init; } = 4;

    /// <summary>Stream schema used for preflight checks before upload.</summary>
    public SentinelSchema Schema { get; init; } = SentinelSchema.Default;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        ArgumentNullException.ThrowIfNull(Endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(DcrImmutableId);
        ArgumentException.ThrowIfNullOrWhiteSpace(StreamName);
        if (!string.Equals(Endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new ArgumentException("Azure ingestion endpoint must use HTTPS.");
        }

        if (MaximumConcurrency is < 1 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumConcurrency));
        }
    }
}

/// <summary>One upload entry: the record exactly as it is sent, and its event id.</summary>
internal sealed class PreparedRecord(string eventId, byte[] utf8Json)
{
    public string EventId { get; } = eventId;

    public ReadOnlyMemory<byte> Utf8Json { get; } = utf8Json;
}

/// <summary>
/// Re-serializes queued payloads into upload entries without building a DOM: one
/// <see cref="Utf8JsonReader"/> pass copied token by token to a <see cref="Utf8JsonWriter"/>
/// with default options. The bytes are what the SDK's JsonObject serializer wrote for
/// <c>JsonNode.Parse(payload)</c>: strings re-escaped with the default encoder, number
/// text, property order and nested repeated names kept, whitespace dropped. Not
/// thread-safe; one instance per delivery.
/// </summary>
internal sealed class RecordEncoder
{
    // JsonNode.Parse(string) rejects invalid UTF-16 instead of replacing it.
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly ArrayBufferWriter<byte> output = new();
    private readonly HashSet<string> names = new(StringComparer.Ordinal);
    private byte[] scratch = [];

    /// <summary>
    /// Encodes one payload. False when it is not a single JSON object within the default
    /// 64-level depth, repeats a top-level property name, or holds invalid text.
    /// </summary>
    public bool TryEncode(
        string payload,
        [NotNullWhen(true)] out byte[]? entry,
        out string? eventId)
    {
        entry = null;
        eventId = null;
        byte[]? utf8 = null;
        try
        {
            utf8 = ArrayPool<byte>.Shared.Rent(StrictUtf8.GetByteCount(payload));
            int length = StrictUtf8.GetBytes(payload, utf8);
            output.ResetWrittenCount();
            names.Clear();
            using (Utf8JsonWriter writer = new(output))
            {
                if (!Copy(utf8.AsSpan(0, length), writer, out eventId))
                {
                    eventId = null;
                    return false;
                }
            }

            entry = output.WrittenSpan.ToArray();
            return true;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException)
        {
            // Malformed JSON, invalid escapes or surrogates, or invalid UTF-16.
            eventId = null;
            return false;
        }
        finally
        {
            if (utf8 is not null)
            {
                ArrayPool<byte>.Shared.Return(utf8);
            }
        }
    }

    private bool Copy(ReadOnlySpan<byte> utf8, Utf8JsonWriter writer, out string? eventId)
    {
        eventId = null;
        // Same limits as JsonNode.Parse: 64-level depth, no comments or trailing commas,
        // nothing after the object.
        Utf8JsonReader reader = new(utf8);
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            return false;
        }

        writer.WriteStartObject();
        bool readingEventId = false;
        while (reader.Read())
        {
            bool eventIdNext = false;
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    writer.WriteStartObject();
                    break;
                case JsonTokenType.EndObject:
                    writer.WriteEndObject();
                    break;
                case JsonTokenType.StartArray:
                    writer.WriteStartArray();
                    break;
                case JsonTokenType.EndArray:
                    writer.WriteEndArray();
                    break;
                case JsonTokenType.PropertyName when reader.CurrentDepth == 1:
                    // JsonObject throws on a repeated top-level name; nested repeats are
                    // copied through, as JsonNode.WriteTo copies nested elements.
                    string name = reader.GetString()!;
                    if (!names.Add(name))
                    {
                        return false;
                    }

                    eventIdNext = string.Equals(name, "eventId", StringComparison.Ordinal);
                    writer.WritePropertyName(name);
                    break;
                case JsonTokenType.PropertyName:
                    writer.WritePropertyName(Unescaped(ref reader));
                    break;
                case JsonTokenType.String:
                    if (readingEventId)
                    {
                        eventId = reader.GetString();
                    }

                    writer.WriteStringValue(Unescaped(ref reader));
                    break;
                case JsonTokenType.Number:
                    // Number text is kept verbatim (JsonElement.WriteTo semantics).
                    writer.WriteRawValue(reader.ValueSpan, skipInputValidation: true);
                    break;
                case JsonTokenType.True:
                    writer.WriteBooleanValue(true);
                    break;
                case JsonTokenType.False:
                    writer.WriteBooleanValue(false);
                    break;
                case JsonTokenType.Null:
                    writer.WriteNullValue();
                    break;
                default:
                    return false;
            }

            readingEventId = eventIdNext;
        }

        writer.Flush();
        return true;
    }

    /// <summary>Unescaped UTF-8 of the current string or property name.</summary>
    private ReadOnlySpan<byte> Unescaped(ref Utf8JsonReader reader)
    {
        if (!reader.ValueIsEscaped)
        {
            return reader.ValueSpan;
        }

        // Unescaping never makes the text longer.
        if (scratch.Length < reader.ValueSpan.Length)
        {
            scratch = new byte[Math.Max(reader.ValueSpan.Length, scratch.Length * 2)];
        }

        int written = reader.CopyString(scratch);
        return scratch.AsSpan(0, written);
    }
}
