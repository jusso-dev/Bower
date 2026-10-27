using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Forwarding;
using Bower.Persistence;

namespace Bower.Collector.Relay;

/// <summary>
/// Accepts one batch from an authenticated downstream collector into the relay's own
/// durable queue. The relay never parses raw source data and never redacts again: each
/// payload is an envelope the downstream already redacted and decided, and it is stored
/// byte for byte, so both ledgers hash the same payload. Validation is default deny: the
/// envelope must parse, name the authenticated collector, carry an accepting policy
/// decision and match its fingerprint. An event answers <c>accepted</c> or <c>duplicate</c>
/// only after its queue transaction committed.
/// </summary>
public sealed class RelayIntake(
    IDurableEventStore queue,
    CollectorSettings settings,
    RelayTelemetry telemetry,
    TimeProvider clock)
{
    public async Task<RelayIntakeOutcome> AcceptAsync(
        string downstreamId,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(downstreamId);
        if (body.Length > RelayProtocol.MaximumRequestBytes)
        {
            return RelayIntakeOutcome.Error(StatusCodes.Status413PayloadTooLarge, "Relay batch is too large.");
        }

        JsonDocument document;
        try
        {
            // Envelope depth 32 plus the batch wrapper.
            document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 40 });
        }
        catch (JsonException)
        {
            return Malformed();
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !TryGetSingle(root, "schemaVersion", out JsonElement version)
                || version.ValueKind != JsonValueKind.Number
                || !version.TryGetInt32(out int schemaVersion)
                || schemaVersion != RelayProtocol.SchemaVersion
                || !TryGetSingle(root, "collectorId", out JsonElement collector)
                || collector.ValueKind != JsonValueKind.String
                || !TryGetSingle(root, "events", out JsonElement events)
                || events.ValueKind != JsonValueKind.Array
                || events.GetArrayLength() is < 1 or > RelayProtocol.MaximumBatchEvents)
            {
                return Malformed();
            }

            // A downstream acts only as the collector its certificate pin names.
            if (!string.Equals(collector.GetString(), downstreamId, StringComparison.Ordinal))
            {
                return RelayIntakeOutcome.Error(
                    StatusCodes.Status403Forbidden,
                    "Relay batch names a collector other than the authenticated downstream.");
            }

            List<Candidate> candidates = new(events.GetArrayLength());
            HashSet<string> seen = new(StringComparer.Ordinal);
            foreach (JsonElement item in events.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object
                    || !TryGetSingle(item, "eventId", out JsonElement eventId)
                    || eventId.ValueKind != JsonValueKind.String
                    || !TryGetSingle(item, "fingerprint", out JsonElement fingerprint)
                    || fingerprint.ValueKind != JsonValueKind.String
                    || !TryGetSingle(item, "payload", out JsonElement payload)
                    || payload.ValueKind != JsonValueKind.Object
                    || string.IsNullOrEmpty(eventId.GetString())
                    || !seen.Add(eventId.GetString()!))
                {
                    return Malformed();
                }

                candidates.Add(new Candidate(eventId.GetString()!, fingerprint.GetString() ?? string.Empty, payload.GetRawText()));
            }

            DateTimeOffset now = clock.GetUtcNow();
            List<RelayEventResult> results = new(candidates.Count);
            int accepted = 0;
            int duplicates = 0;
            int rejected = 0;
            try
            {
                foreach (Candidate candidate in candidates)
                {
                    RelayEventResult result = await AcceptOneAsync(downstreamId, candidate, now, cancellationToken);
                    results.Add(result);
                    switch (result.Status)
                    {
                        case RelayEventStatuses.Accepted:
                            accepted++;
                            break;
                        case RelayEventStatuses.Duplicate:
                            duplicates++;
                            break;
                        default:
                            rejected++;
                            break;
                    }
                }
            }
            catch (QueueCapacityExceededException)
            {
                // Events committed before the queue filled answer duplicate on the retry.
                telemetry.RecordBatch(downstreamId, accepted, duplicates, rejected, now);
                return RelayIntakeOutcome.Error(
                    StatusCodes.Status503ServiceUnavailable,
                    "Relay queue is at capacity; retry later.");
            }

            telemetry.RecordBatch(downstreamId, accepted, duplicates, rejected, now);
            LedgerHead head = await queue.GetLedgerHeadAsync(cancellationToken);
            return new RelayIntakeOutcome(
                StatusCodes.Status200OK,
                new RelayBatchResponse(
                    RelayProtocol.SchemaVersion,
                    settings.CollectorId,
                    new RelayLedgerHead(head.Sequence, head.Hash),
                    results),
                null);
        }
    }

    private async Task<RelayEventResult> AcceptOneAsync(
        string downstreamId,
        Candidate candidate,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (Encoding.UTF8.GetByteCount(candidate.Payload) > RelayProtocol.MaximumPayloadBytes)
        {
            return Rejected(candidate, RelayRejectCodes.PayloadTooLarge);
        }

        SecurityEventEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize(candidate.Payload, BowerJson.Envelope);
        }
        catch (JsonException)
        {
            envelope = null;
        }

        if (envelope is null)
        {
            return Rejected(candidate, RelayRejectCodes.PayloadInvalid);
        }

        if (!string.Equals(envelope.EventId, candidate.EventId, StringComparison.Ordinal))
        {
            return Rejected(candidate, RelayRejectCodes.EventIdMismatch);
        }

        if (!string.Equals(envelope.Collector?.Id, downstreamId, StringComparison.Ordinal))
        {
            return Rejected(candidate, RelayRejectCodes.CollectorMismatch);
        }

        // Only what a collector's policy accepted reaches a queue; anything else is not
        // post-decision data and the relay refuses to carry it.
        if (envelope.Security?.Decision is not (DecisionAction.Accept or DecisionAction.RedactAndAccept or DecisionAction.Aggregate))
        {
            return Rejected(candidate, RelayRejectCodes.PolicyDecisionMissing);
        }

        if (!string.Equals(EventIdentity.Create(envelope), candidate.Fingerprint, StringComparison.Ordinal))
        {
            return Rejected(candidate, RelayRejectCodes.FingerprintMismatch);
        }

        try
        {
            EnqueueResult enqueue = await queue.EnqueueAsync(
                new QueuedEvent(candidate.EventId, candidate.Fingerprint, candidate.Payload, now),
                cancellationToken);
            return new RelayEventResult(
                candidate.EventId,
                enqueue.Duplicate ? RelayEventStatuses.Duplicate : RelayEventStatuses.Accepted);
        }
        catch (EventIdentityConflictException)
        {
            return Rejected(candidate, RelayRejectCodes.IdentityConflict);
        }
        catch (ArgumentException)
        {
            // The queue's own constraints (for example an event id over 128 characters).
            return Rejected(candidate, RelayRejectCodes.PayloadInvalid);
        }
    }

    private static RelayEventResult Rejected(Candidate candidate, string code) =>
        new(candidate.EventId, RelayEventStatuses.Rejected) { Code = code };

    private static RelayIntakeOutcome Malformed() =>
        RelayIntakeOutcome.Error(StatusCodes.Status400BadRequest, "Relay batch is malformed.");

    /// <summary>Exactly one property with this name (a repeated key is refused, not last-wins).</summary>
    private static bool TryGetSingle(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        int count = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                value = property.Value;
                count++;
            }
        }

        return count == 1;
    }

    private sealed record Candidate(string EventId, string Fingerprint, string Payload);
}

public sealed record RelayIntakeOutcome(int StatusCode, RelayBatchResponse? Response, string? Message)
{
    public static RelayIntakeOutcome Error(int statusCode, string message) => new(statusCode, null, message);
}
