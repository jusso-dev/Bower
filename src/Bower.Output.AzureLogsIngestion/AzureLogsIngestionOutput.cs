using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Serialization;
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

    private static readonly JsonRecordSerializer RecordSerializer = new();

    public string Id => options.Id;

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        if (events.Count == 0)
        {
            return new DeliveryResult([], [], null);
        }

        // The SDK reports failed logs by the objects it was given, so failures map back to
        // events by the eventId each record carries. The queue guarantees ids are unique.
        HashSet<string> batchEventIds = new(StringComparer.Ordinal);
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
            else
            {
                records.Add(new PreparedRecord(item.EventId, entry));
                batchEventIds.Add(item.EventId);
            }
        }

        if (records.Count == 0)
        {
            return new DeliveryResult([], failures, null);
        }

        ConcurrentDictionary<string, DeliveryFailure> uploadFailures = new(StringComparer.Ordinal);
        int unattributed = 0;
        LogsUploadOptions uploadOptions = new()
        {
            MaxConcurrency = options.MaximumConcurrency,
            // Copies the prepared bytes, so the SDK never falls back to reflection.
            Serializer = RecordSerializer
        };
        uploadOptions.UploadFailed += args =>
        {
            int status = args.Exception is RequestFailedException requestFailure
                ? requestFailure.Status
                : 0;
            foreach (object failedLog in args.FailedLogs)
            {
                string? eventId = failedLog switch
                {
                    PreparedRecord record => record.EventId,
                    BinaryData data => RecordEncoder.TryReadEventId(data.ToMemory().Span),
                    _ => null
                };
                if (eventId is not null && batchEventIds.Contains(eventId))
                {
                    uploadFailures[eventId] = new DeliveryFailure(
                        eventId,
                        status == 0 ? "azure-upload-failed" : $"azure-http-{status}",
                        status is 0 or 408 or 429 or >= 500,
                        null);
                }
                else
                {
                    Interlocked.Increment(ref unattributed);
                }
            }

            return Task.CompletedTask;
        };

        Response response = await UploadAsync(records, uploadOptions, cancellationToken);

        if (Volatile.Read(ref unattributed) > 0)
        {
            // A failure that cannot be tied to an event must never be counted as delivered.
            failures.AddRange(batchEventIds
                .Select(eventId => new DeliveryFailure(eventId, "azure-upload-unattributed", true, null)));
            return new DeliveryResult([], failures, null);
        }

        failures.AddRange(uploadFailures.Values);
        string[] acknowledged = batchEventIds
            .Where(eventId => !uploadFailures.ContainsKey(eventId))
            .ToArray();

        // Ingestion API acceptance only. Sentinel queryability is proven separately.
        string acknowledgement =
            $"azure-logs-ingestion:accepted:{response.Headers.RequestId ?? $"http-{response.Status}"}";
        return new DeliveryResult(acknowledged, failures, acknowledgement);
    }

    // UploadAsync<T> is annotated RequiresUnreferencedCode/RequiresDynamicCode only because
    // it serializes each T with LogsUploadOptions.Serializer, which defaults to the
    // reflection-based JsonObjectSerializer. Every call passes RecordSerializer, which
    // copies each PreparedRecord's bytes (no type metadata), and T is PreparedRecord, so
    // nothing is reached through reflection and no code is generated at run time. The
    // guard below keeps that true; AzureLogsIngestionOutputTests pin the uploaded bytes.
    [UnconditionalSuppressMessage(
        "Trimming",
        "IL2026:RequiresUnreferencedCode",
        Justification = "Records are pre-serialized bytes written by JsonRecordSerializer without reflection.")]
    [UnconditionalSuppressMessage(
        "AOT",
        "IL3050:RequiresDynamicCode",
        Justification = "Records are pre-serialized bytes written by JsonRecordSerializer without reflection.")]
    private Task<Response> UploadAsync(
        List<PreparedRecord> records,
        LogsUploadOptions uploadOptions,
        CancellationToken cancellationToken)
    {
        if (!ReferenceEquals(uploadOptions.Serializer, RecordSerializer))
        {
            throw new InvalidOperationException("Log records must use the prepared-record serializer.");
        }

        return client.UploadAsync(
            options.DcrImmutableId,
            options.StreamName,
            records,
            uploadOptions,
            cancellationToken);
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

    /// <summary>The top-level string <c>eventId</c> of an encoded entry, if any.</summary>
    public static string? TryReadEventId(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            Utf8JsonReader reader = new(utf8Json);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool match = reader.ValueTextEquals("eventId"u8);
                reader.Read();
                if (match)
                {
                    return reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
                }

                reader.Skip();
            }

            return null;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
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

/// <summary>
/// Writes <see cref="PreparedRecord"/> entries for the Logs Ingestion SDK without
/// reflection: the prepared bytes, unchanged.
/// </summary>
internal sealed class JsonRecordSerializer : ObjectSerializer
{
    public override void Serialize(Stream stream, object? value, Type inputType, CancellationToken cancellationToken) =>
        stream.Write(Bytes(value).Span);

    public override async ValueTask SerializeAsync(
        Stream stream,
        object? value,
        Type inputType,
        CancellationToken cancellationToken) =>
        await stream.WriteAsync(Bytes(value), cancellationToken);

    public override BinaryData Serialize(object? value, Type? inputType = null, CancellationToken cancellationToken = default) =>
        new(Bytes(value));

    public override ValueTask<BinaryData> SerializeAsync(
        object? value,
        Type? inputType = null,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new BinaryData(Bytes(value)));

    public override object? Deserialize(Stream stream, Type returnType, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Log records are write-only.");

    public override ValueTask<object?> DeserializeAsync(Stream stream, Type returnType, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Log records are write-only.");

    private static ReadOnlyMemory<byte> Bytes(object? value) => value switch
    {
        PreparedRecord record => record.Utf8Json,
        null => "null"u8.ToArray(),
        _ => throw new NotSupportedException($"Unsupported log record type {value.GetType().Name}.")
    };
}
