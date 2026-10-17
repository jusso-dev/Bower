using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
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

        // The SDK reports failed logs as serialised BinaryData, so failures map back to
        // events by the eventId inside each record. The queue guarantees ids are unique.
        HashSet<string> batchEventIds = new(StringComparer.Ordinal);
        List<JsonObject> records = new(events.Count);
        List<DeliveryFailure> failures = [];
        foreach (QueuedEvent item in events)
        {
            JsonObject? record = TryParseRecord(item.Payload);
            if (record is null)
            {
                // A payload that cannot be parsed will never succeed: dead-letter it alone
                // instead of failing the whole batch.
                failures.Add(new DeliveryFailure(item.EventId, "payload-invalid-json", false, null));
            }
            else if (!string.Equals(ReadEventId(record), item.EventId, StringComparison.Ordinal))
            {
                failures.Add(new DeliveryFailure(item.EventId, "payload-event-id-mismatch", false, null));
            }
            else if (IngestionPreflight.Check(record, options.Schema) is { Count: > 0 } issues)
            {
                // Azure would truncate, coerce or drop this row silently; dead-letter it
                // with the reason instead.
                failures.Add(new DeliveryFailure(item.EventId, $"preflight-{issues[0].Code}", false, null));
            }
            else
            {
                records.Add(record);
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
            // Source-generated metadata, so the SDK never falls back to reflection.
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
                    BinaryData data => ReadEventId(TryParseRecord(data.ToString())),
                    JsonObject record => ReadEventId(record),
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

    private static string? ReadEventId(JsonObject? record) =>
        record?["eventId"] is JsonValue value && value.TryGetValue(out string? eventId)
            ? eventId
            : null;

    // UploadAsync<T> is annotated RequiresUnreferencedCode/RequiresDynamicCode only because
    // it serializes each T with LogsUploadOptions.Serializer, which defaults to the
    // reflection-based JsonObjectSerializer. Every call passes RecordSerializer, which
    // writes JsonObject nodes directly (JsonNode.WriteTo, no type metadata), and T is
    // JsonObject, so nothing is reached through reflection and no code is generated at
    // run time. The guard below keeps that true; AzureLogsIngestionOutputTests pin the
    // uploaded bytes.
    [UnconditionalSuppressMessage(
        "Trimming",
        "IL2026:RequiresUnreferencedCode",
        Justification = "Records are JsonObject written by JsonRecordSerializer without reflection.")]
    [UnconditionalSuppressMessage(
        "AOT",
        "IL3050:RequiresDynamicCode",
        Justification = "Records are JsonObject written by JsonRecordSerializer without reflection.")]
    private Task<Response> UploadAsync(
        List<JsonObject> records,
        LogsUploadOptions uploadOptions,
        CancellationToken cancellationToken)
    {
        if (!ReferenceEquals(uploadOptions.Serializer, RecordSerializer))
        {
            throw new InvalidOperationException("Log records must use the source-generated serializer.");
        }

        return client.UploadAsync(
            options.DcrImmutableId,
            options.StreamName,
            records,
            uploadOptions,
            cancellationToken);
    }

    private static JsonObject? TryParseRecord(string payload)
    {
        try
        {
            return JsonNode.Parse(payload) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
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

/// <summary>
/// Writes log records for the Logs Ingestion SDK without reflection: each record is a
/// <see cref="JsonObject"/> and is written with default writer options, byte-for-byte what
/// the SDK's default <c>JsonObjectSerializer</c> produced for the same node.
/// </summary>
internal sealed class JsonRecordSerializer : ObjectSerializer
{
    public override void Serialize(Stream stream, object? value, Type inputType, CancellationToken cancellationToken)
    {
        using Utf8JsonWriter writer = new(stream);
        Write(writer, value);
    }

    public override async ValueTask SerializeAsync(
        Stream stream,
        object? value,
        Type inputType,
        CancellationToken cancellationToken)
    {
        await using Utf8JsonWriter writer = new(stream);
        Write(writer, value);
        await writer.FlushAsync(cancellationToken);
    }

    public override BinaryData Serialize(object? value, Type? inputType = null, CancellationToken cancellationToken = default)
    {
        using MemoryStream stream = new();
        Serialize(stream, value, inputType ?? typeof(JsonObject), cancellationToken);
        return new BinaryData(stream.ToArray());
    }

    public override async ValueTask<BinaryData> SerializeAsync(
        object? value,
        Type? inputType = null,
        CancellationToken cancellationToken = default)
    {
        using MemoryStream stream = new();
        await SerializeAsync(stream, value, inputType ?? typeof(JsonObject), cancellationToken);
        return new BinaryData(stream.ToArray());
    }

    public override object? Deserialize(Stream stream, Type returnType, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Log records are write-only.");

    public override ValueTask<object?> DeserializeAsync(Stream stream, Type returnType, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Log records are write-only.");

    private static void Write(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case JsonNode node:
                node.WriteTo(writer);
                break;
            case null:
                writer.WriteNullValue();
                break;
            default:
                throw new NotSupportedException($"Unsupported log record type {value.GetType().Name}.");
        }

        writer.Flush();
    }
}
