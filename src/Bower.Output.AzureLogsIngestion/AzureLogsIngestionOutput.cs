using System.Collections.Concurrent;
using System.Text.Json;
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
        TokenCredential credential)
    {
        options.Validate();
        this.options = options;
        client = new LogsIngestionClient(options.Endpoint, credential);
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

        Dictionary<string, string> payloadToEvent = new(StringComparer.Ordinal);
        List<JsonElement> records = [];
        foreach (QueuedEvent item in events)
        {
            using JsonDocument document = JsonDocument.Parse(item.Payload);
            JsonElement record = document.RootElement.Clone();
            records.Add(record);
            payloadToEvent[record.GetRawText()] = item.EventId;
        }

        ConcurrentDictionary<string, DeliveryFailure> failures = new(StringComparer.Ordinal);
        LogsUploadOptions uploadOptions = new()
        {
            MaxConcurrency = options.MaximumConcurrency
        };
        uploadOptions.UploadFailed += args =>
        {
            foreach (object failedLog in args.FailedLogs)
            {
                string raw = failedLog is JsonElement element
                    ? element.GetRawText()
                    : JsonSerializer.Serialize(failedLog);
                if (!payloadToEvent.TryGetValue(raw, out string? eventId))
                {
                    continue;
                }

                int status = args.Exception is RequestFailedException requestFailure
                    ? requestFailure.Status
                    : 0;
                failures[eventId] = new DeliveryFailure(
                    eventId,
                    status == 0 ? "azure-upload-failed" : $"azure-http-{status}",
                    status is 0 or 408 or 429 or >= 500,
                    null);
            }

            return Task.CompletedTask;
        };

        Response response = await client.UploadAsync(
            options.DcrImmutableId,
            options.StreamName,
            records,
            uploadOptions,
            cancellationToken);

        string acknowledgement = response.Headers.RequestId ?? $"azure-http-{response.Status}";
        string[] acknowledged = events
            .Where(item => !failures.ContainsKey(item.EventId))
            .Select(item => item.EventId)
            .ToArray();
        return new DeliveryResult(acknowledged, failures.Values.ToArray(), acknowledgement);
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
