using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;

namespace Bower.Forwarding;

/// <summary>
/// Output for a downstream collector behind a relay (BOWER_OUTPUT=relay). Posts leased
/// events, already redacted and decided, to the relay exactly as the queue stores them.
/// The at-least-once rule of <see cref="CollectorClient"/> applies across the hop: an event
/// is acknowledged only when the relay reports it committed (accepted) or already held
/// (duplicate). Everything else stays in this collector's queue. The HttpClient carries the
/// mutual TLS client certificate and BOWER_RELAY_URL as its base address.
/// </summary>
public sealed class RelayOutput(HttpClient client, string collectorId, TimeProvider? clock = null) : IOutputAdapter
{
    public const string OutputId = "relay";

    private static readonly TimeSpan MaximumRequestDuration = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromHours(1);
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    public string Id => OutputId;

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        List<DeliveryFailure> failures = [];
        List<List<(QueuedEvent Event, byte[] Payload)>> batches = [];
        List<(QueuedEvent Event, byte[] Payload)> current = [];
        int bytes = 0;
        foreach (QueuedEvent item in events)
        {
            byte[] payload = Encoding.UTF8.GetBytes(item.Payload);
            if (payload.Length > RelayProtocol.MaximumPayloadBytes)
            {
                failures.Add(new DeliveryFailure(item.EventId, "payload-too-large", false, null));
                continue;
            }

            if (!IsJsonObject(payload))
            {
                // Never succeeds anywhere: dead-letter it alone, as the Azure output does.
                failures.Add(new DeliveryFailure(item.EventId, "payload-invalid-json", false, null));
                continue;
            }

            if (current.Count > 0
                && (current.Count == RelayProtocol.MaximumBatchEvents
                    || bytes + payload.Length > RelayProtocol.TargetBatchPayloadBytes))
            {
                batches.Add(current);
                current = [];
                bytes = 0;
            }

            current.Add((item, payload));
            bytes += payload.Length;
        }

        if (current.Count > 0)
        {
            batches.Add(current);
        }

        List<string> acknowledged = [];
        string? acknowledgement = null;
        for (int index = 0; index < batches.Count; index++)
        {
            BatchOutcome outcome = await SendAsync(batches[index], cancellationToken);
            acknowledged.AddRange(outcome.Acknowledged);
            failures.AddRange(outcome.Failures);
            acknowledgement = outcome.Acknowledgement ?? acknowledgement;
            if (outcome.DestinationFailure is { } stop)
            {
                // The relay is unavailable: keep the rest queued behind the destination
                // circuit instead of sending them into the same failure.
                foreach ((QueuedEvent item, _) in batches.Skip(index + 1).SelectMany(batch => batch))
                {
                    failures.Add(stop with { EventId = item.EventId });
                }

                break;
            }
        }

        return new DeliveryResult(acknowledged, failures, acknowledgement);
    }

    private async Task<BatchOutcome> SendAsync(
        List<(QueuedEvent Event, byte[] Payload)> batch,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, RelayProtocol.BatchPath)
        {
            Content = new ByteArrayContent(Serialize(batch))
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        HttpStatusCode status;
        DateTimeOffset? retryAfter;
        byte[]? body = null;
        // ResponseHeadersRead ends HttpClient.Timeout at the headers. Keep a deadline
        // through the bounded body read so a stalled relay cannot hold delivery forever.
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(client.Timeout != Timeout.InfiniteTimeSpan && client.Timeout < MaximumRequestDuration
            ? client.Timeout
            : MaximumRequestDuration);
        try
        {
            using HttpResponseMessage response = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            status = response.StatusCode;
            retryAfter = ReadRetryAfter(response.Headers.RetryAfter);
            if (status == HttpStatusCode.OK)
            {
                body = await ReadBoundedAsync(response.Content, deadline.Token);
            }
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException
                || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Transport and TLS failures. Exception text is never kept.
            return Fail(batch, new DeliveryFailure(string.Empty, "destination-relay-unavailable", true, null));
        }

        if (status != HttpStatusCode.OK)
        {
            int code = (int)status;
            bool destination = code is 401 or 403 or 404 or 408 or 429 or >= 500;
            // A relay-wide refusal holds the stream (no poison budget spent). Any other 4xx
            // means this request was refused: retry with the attempt budget.
            return Fail(batch, new DeliveryFailure(
                string.Empty,
                destination ? $"destination-relay-http-{code}" : $"relay-http-{code}",
                true,
                retryAfter));
        }

        RelayBatchResponse? parsed = Parse(body);
        if (parsed is null)
        {
            return Fail(batch, new DeliveryFailure(string.Empty, "destination-relay-response-invalid", true, null));
        }

        Dictionary<string, RelayEventResult> results = new(StringComparer.Ordinal);
        HashSet<string> sent = batch.Select(item => item.Event.EventId).ToHashSet(StringComparer.Ordinal);
        foreach (RelayEventResult result in parsed.Results)
        {
            if (!sent.Contains(result.EventId) || !results.TryAdd(result.EventId, result)
                || result.Status is not (RelayEventStatuses.Accepted or RelayEventStatuses.Duplicate or RelayEventStatuses.Rejected))
            {
                return Fail(batch, new DeliveryFailure(string.Empty, "destination-relay-response-invalid", true, null));
            }
        }

        List<string> acknowledged = [];
        List<DeliveryFailure> failures = [];
        foreach ((QueuedEvent item, _) in batch)
        {
            if (!results.TryGetValue(item.EventId, out RelayEventResult? result))
            {
                failures.Add(new DeliveryFailure(item.EventId, "destination-relay-result-missing", true, null));
            }
            else if (result.Status is RelayEventStatuses.Accepted or RelayEventStatuses.Duplicate)
            {
                acknowledged.Add(item.EventId);
            }
            else
            {
                // An explicit rejection is permanent, so it is dead-lettered here,
                // where the operator who owns the source can see it.
                string code = result.Status == RelayEventStatuses.Rejected && RelayProtocol.IsValidCode(result.Code)
                    ? result.Code!
                    : "unknown";
                failures.Add(new DeliveryFailure(item.EventId, $"relay-rejected:{code}", false, null));
            }
        }

        return new BatchOutcome(
            acknowledged,
            failures,
            acknowledged.Count == 0
                ? null
                : string.Create(CultureInfo.InvariantCulture, $"relay:{parsed.RelayId}:ledger:{parsed.Ledger.Sequence}"),
            failures.FirstOrDefault(failure => failure.IsDestinationFailure));
    }

    private static BatchOutcome Fail(
        List<(QueuedEvent Event, byte[] Payload)> batch,
        DeliveryFailure failure)
    {
        DeliveryFailure[] failures = [.. batch.Select(item => failure with { EventId = item.Event.EventId })];
        return new BatchOutcome([], failures, null, failure.IsDestinationFailure ? failure : null);
    }

    private byte[] Serialize(List<(QueuedEvent Event, byte[] Payload)> batch)
    {
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { SkipValidation = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", RelayProtocol.SchemaVersion);
            writer.WriteString("collectorId", collectorId);
            writer.WriteStartArray("events");
            foreach ((QueuedEvent item, byte[] payload) in batch)
            {
                writer.WriteStartObject();
                writer.WriteString("eventId", item.EventId);
                writer.WriteString("fingerprint", item.Fingerprint);
                // The stored bytes, unchanged: the relay's ledger then hashes the same payload.
                writer.WritePropertyName("payload");
                writer.WriteRawValue(payload, skipInputValidation: true);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static bool IsJsonObject(byte[] payload)
    {
        try
        {
            Utf8JsonReader reader = new(payload, new JsonReaderOptions { MaxDepth = 64 });
            return reader.Read()
                && reader.TokenType == JsonTokenType.StartObject
                && reader.TrySkip()
                && !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static RelayBatchResponse? Parse(byte[]? body)
    {
        if (body is null)
        {
            return null;
        }

        try
        {
            RelayBatchResponse? response = JsonSerializer.Deserialize(body, RelayJsonContext.Default.RelayBatchResponse);
            return response is { SchemaVersion: RelayProtocol.SchemaVersion, Results: not null, Ledger: not null }
                && RelayProtocol.IsValidIdentifier(response.RelayId)
                && response.Ledger.Sequence >= 0
                && response.Results.All(result => result is { EventId: not null, Status: not null })
                    ? response
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > RelayProtocol.MaximumResponseBytes)
        {
            return null;
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream copy = new();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (copy.Length + read > RelayProtocol.MaximumResponseBytes)
                {
                    return null;
                }

                copy.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return copy.ToArray();
    }

    private DateTimeOffset? ReadRetryAfter(RetryConditionHeaderValue? header)
    {
        DateTimeOffset now = time.GetUtcNow();
        DateTimeOffset? at = header?.Delta is { } delta ? now.Add(delta) : header?.Date;
        return at is null || at <= now ? null : at > now.Add(MaximumRetryAfter) ? now.Add(MaximumRetryAfter) : at;
    }

    private sealed record BatchOutcome(
        IReadOnlyList<string> Acknowledged,
        IReadOnlyList<DeliveryFailure> Failures,
        string? Acknowledgement,
        DeliveryFailure? DestinationFailure);
}
