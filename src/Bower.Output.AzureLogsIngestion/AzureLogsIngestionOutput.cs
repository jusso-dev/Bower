using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;

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
            MaxConcurrency = options.MaximumConcurrency
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

        Response response = await client.UploadAsync(
            options.DcrImmutableId,
            options.StreamName,
            records,
            uploadOptions,
            cancellationToken);

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
