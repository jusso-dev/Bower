using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.Core;

public sealed class SecurityEventProcessor(
    IEventRedactor redactor,
    ITelemetryPolicyEvaluator policyEvaluator,
    IDurableEventStore queue,
    IClock clock)
{
    public async Task<ProcessingResult> ProcessAsync(
        string candidateJson,
        CollectorIdentity collector,
        CancellationToken cancellationToken = default)
    {
        RedactionResult redaction = redactor.Redact(candidateJson);
        if (!redaction.Succeeded || redaction.RedactedJson is null)
        {
            return ProcessingResult.Failed(
                DecisionAction.Quarantine,
                redaction.FailureCode ?? "redaction-failed");
        }

        SecurityEventEnvelope? candidate;
        try
        {
            candidate = JsonSerializer.Deserialize<SecurityEventEnvelope>(
                redaction.RedactedJson,
                BowerJson.Options);
        }
        catch (JsonException)
        {
            return ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid");
        }

        if (candidate is null)
        {
            return ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid");
        }

        List<string> validationFailures = Validate(candidate, clock.UtcNow);
        if (validationFailures.Count > 0)
        {
            return new ProcessingResult(
                DecisionAction.Quarantine,
                candidate.EventId,
                false,
                false,
                validationFailures,
                null);
        }

        PolicyDecision decision = policyEvaluator.Evaluate(candidate);
        if (decision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            return new ProcessingResult(
                decision.Action,
                candidate.EventId,
                false,
                false,
                decision.Reasons.Concat(decision.Warnings).ToArray(),
                decision);
        }

        SecurityEventEnvelope arranged = candidate with
        {
            TimeObserved = candidate.TimeObserved ?? clock.UtcNow,
            Security = new SecurityDecisionContext
            {
                PolicyId = decision.PolicyId,
                PolicyVersion = decision.PolicyVersion,
                PolicyHash = decision.PolicyHash,
                ValueScore = decision.Score,
                Decision = redaction.RemovedPaths.Count > 0 || redaction.MaskedPaths.Count > 0
                    ? DecisionAction.RedactAndAccept
                    : DecisionAction.Accept,
                ClassificationReasons = decision.Reasons
            },
            Collector = new CollectorContext
            {
                Id = collector.Id,
                Version = collector.Version,
                SourceAdapter = collector.SourceAdapter,
                ConfigurationHash = collector.ConfigurationHash,
                ReceivedAt = clock.UtcNow
            }
        };

        string payload = JsonSerializer.Serialize(arranged, BowerJson.Options);
        QueuedEvent queued = new(
            arranged.EventId,
            EventFingerprint.Create(arranged),
            payload,
            clock.UtcNow);
        EnqueueResult enqueue = await queue.EnqueueAsync(queued, cancellationToken);

        List<string> reasons = [.. decision.Reasons, .. decision.Warnings];
        if (redaction.RemovedPaths.Count > 0)
        {
            reasons.Add($"Removed {redaction.RemovedPaths.Count} prohibited field(s)");
        }

        if (redaction.MaskedPaths.Count > 0)
        {
            reasons.Add($"Masked {redaction.MaskedPaths.Count} personal field(s)");
        }

        if (enqueue.Duplicate)
        {
            reasons.Add("Duplicate fingerprint already present");
        }

        return new ProcessingResult(
            arranged.Security.Decision,
            arranged.EventId,
            enqueue.Enqueued,
            enqueue.Duplicate,
            reasons,
            decision);
    }

    private static List<string> Validate(
        SecurityEventEnvelope candidate,
        DateTimeOffset now)
    {
        List<string> failures = [];
        if (!string.Equals(
                candidate.SchemaVersion,
                SecurityEventEnvelope.CurrentSchemaVersion,
                StringComparison.Ordinal))
        {
            failures.Add("Unsupported schemaVersion");
        }

        if (string.IsNullOrWhiteSpace(candidate.EventId) || candidate.EventId.Length > 128)
        {
            failures.Add("eventId is required and must not exceed 128 characters");
        }

        if (string.IsNullOrWhiteSpace(candidate.EventType)
            || string.IsNullOrWhiteSpace(candidate.EventCategory)
            || string.IsNullOrWhiteSpace(candidate.EventAction))
        {
            failures.Add("eventType, eventCategory and eventAction are required");
        }

        if (candidate.Application is null
            || string.IsNullOrWhiteSpace(candidate.Application.Name)
            || string.IsNullOrWhiteSpace(candidate.Application.Environment))
        {
            failures.Add("application.name and application.environment are required");
        }

        if (candidate.TimeGenerated == default
            || candidate.TimeGenerated > now.AddMinutes(5)
            || candidate.TimeGenerated < now.AddYears(-5))
        {
            failures.Add("timeGenerated is outside allowed range");
        }

        return failures;
    }
}

public sealed record CollectorIdentity(
    string Id,
    string Version,
    string SourceAdapter,
    string ConfigurationHash);

public sealed record ProcessingResult(
    DecisionAction Action,
    string? EventId,
    bool Queued,
    bool Duplicate,
    IReadOnlyList<string> Reasons,
    PolicyDecision? PolicyDecision)
{
    public static ProcessingResult Failed(DecisionAction action, string reason)
    {
        return new ProcessingResult(action, null, false, false, [reason], null);
    }
}
