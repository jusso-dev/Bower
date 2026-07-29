using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Redaction.Privacy;

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
            // Still notify SOC when high-risk secrets/PII were present in invalid payloads.
            string? alertId = await TryEnqueuePrivacyAlertAsync(
                candidate,
                redaction,
                collector,
                cancellationToken);

            return new ProcessingResult(
                DecisionAction.Quarantine,
                candidate.EventId,
                false,
                false,
                validationFailures,
                null,
                alertId);
        }

        PolicyDecision decision = policyEvaluator.Evaluate(candidate);
        if (decision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            string? rejectedAlertId = await TryEnqueuePrivacyAlertAsync(
                candidate,
                redaction,
                collector,
                cancellationToken);

            return new ProcessingResult(
                decision.Action,
                candidate.EventId,
                false,
                false,
                decision.Reasons.Concat(decision.Warnings).ToArray(),
                decision,
                rejectedAlertId);
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
                Decision = redaction.RemovedPaths.Count > 0
                    || redaction.MaskedPaths.Count > 0
                    || (redaction.PrivacyDetected?.Count > 0)
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

        string? privacyAlertEventId = await TryEnqueuePrivacyAlertAsync(
            arranged,
            redaction,
            collector,
            cancellationToken);

        List<string> reasons = [.. decision.Reasons, .. decision.Warnings];
        if (redaction.RemovedPaths.Count > 0)
        {
            reasons.Add($"Removed {redaction.RemovedPaths.Count} prohibited field(s)");
        }

        if (redaction.MaskedPaths.Count > 0)
        {
            reasons.Add($"Masked {redaction.MaskedPaths.Count} personal field(s)");
        }

        if (privacyAlertEventId is not null)
        {
            reasons.Add($"Emitted privacy alert event {privacyAlertEventId}");
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
            decision,
            privacyAlertEventId);
    }

    private async Task<string?> TryEnqueuePrivacyAlertAsync(
        SecurityEventEnvelope source,
        RedactionResult redaction,
        CollectorIdentity collector,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> detected = redaction.PrivacyDetected ?? [];
        IReadOnlyDictionary<string, string> actions =
            redaction.PrivacyActions ?? new Dictionary<string, string>();

        List<string> alertWorthy = detected
            .Where(PrivacyEngine.IsSecurityEventWorthy)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        if (alertWorthy.Count == 0)
        {
            return null;
        }

        Dictionary<string, string> alertActions = new(StringComparer.Ordinal);
        foreach (string id in alertWorthy)
        {
            string root = id;
            int colon = id.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                root = id[..colon];
            }

            if (actions.TryGetValue(root, out string? label))
            {
                alertActions[root] = label;
            }
            else if (actions.TryGetValue(id, out string? fullLabel))
            {
                alertActions[id] = fullLabel;
            }
        }

        EventSeverity severity = ResolveSeverity(alertWorthy);
        DateTimeOffset now = clock.UtcNow;
        // Stable correlation for fingerprint: one alert per source event + detector set.
        string detectorFingerprint = string.Join(',', alertWorthy);
        string alertEventId = TruncateId($"privacy-{source.EventId}-{Guid.NewGuid():N}");
        SecurityEventEnvelope alert = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = alertEventId,
            EventOriginalId = TruncateId($"{source.EventId}:{detectorFingerprint}"),
            TimeGenerated = now,
            TimeObserved = now,
            EventCategory = SecurityEventCategories.PrivacyControl,
            EventType = SecurityEventTypes.SensitiveDataDetected,
            EventAction = "privacy.control.applied",
            EventResult = EventResult.Success,
            EventSeverity = severity,
            EventOutcomeReason =
                $"Privacy engine applied controls for {alertWorthy.Count} high-risk finding(s)",
            Application = source.Application,
            Actor = new ActorContext
            {
                Type = ActorType.System,
                Username = "bower.privacy-engine",
                DisplayName = "Bower Privacy & Secret Protection Engine"
            },
            Target = new TargetContext
            {
                Type = "telemetry_event",
                Id = source.EventId,
                Name = source.EventType
            },
            Source = source.Source,
            Request = source.Request is null
                ? new RequestContext { CorrelationId = source.EventId }
                : source.Request with
                {
                    CorrelationId = source.Request.CorrelationId ?? source.EventId
                },
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["sourceEventId"] = source.EventId,
                ["sourceEventType"] = source.EventType,
                ["sourceEventCategory"] = source.EventCategory,
                ["detectorFingerprint"] = detectorFingerprint
            },
            Privacy = new PrivacyContext
            {
                Detected = alertWorthy,
                Actions = alertActions
            },
            Collector = new CollectorContext
            {
                Id = collector.Id,
                Version = collector.Version,
                SourceAdapter = collector.SourceAdapter,
                ConfigurationHash = collector.ConfigurationHash,
                ReceivedAt = now
            }
        };

        PolicyDecision alertDecision = policyEvaluator.Evaluate(alert);
        if (alertDecision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            return null;
        }

        SecurityEventEnvelope arrangedAlert = alert with
        {
            Security = new SecurityDecisionContext
            {
                PolicyId = alertDecision.PolicyId,
                PolicyVersion = alertDecision.PolicyVersion,
                PolicyHash = alertDecision.PolicyHash,
                ValueScore = alertDecision.Score,
                Decision = DecisionAction.Accept,
                ClassificationReasons = alertDecision.Reasons
            }
        };

        string payload = JsonSerializer.Serialize(arrangedAlert, BowerJson.Options);
        QueuedEvent queued = new(
            arrangedAlert.EventId,
            EventFingerprint.Create(arrangedAlert),
            payload,
            now);
        EnqueueResult enqueue = await queue.EnqueueAsync(queued, cancellationToken);
        return enqueue.Enqueued || enqueue.Duplicate ? arrangedAlert.EventId : null;
    }

    private static EventSeverity ResolveSeverity(IReadOnlyList<string> detectors)
    {
        foreach (string id in detectors)
        {
            string root = id.Split(':')[0];
            if (root.StartsWith("secret.", StringComparison.Ordinal)
                || root.StartsWith("crypto.", StringComparison.Ordinal)
                || root is DetectorIds.CreditCard or DetectorIds.Tfn or DetectorIds.FieldNameSecret)
            {
                return EventSeverity.High;
            }
        }

        return EventSeverity.Medium;
    }

    private static string TruncateId(string value) =>
        value.Length <= 128 ? value : value[..128];

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
    PolicyDecision? PolicyDecision,
    string? PrivacyAlertEventId = null)
{
    public static ProcessingResult Failed(DecisionAction action, string reason)
    {
        return new ProcessingResult(action, null, false, false, [reason], null);
    }
}
