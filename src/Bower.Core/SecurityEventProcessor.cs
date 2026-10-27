using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Persistence;
using Bower.Redaction.Privacy;

namespace Bower.Core;

public sealed class SecurityEventProcessor(
    IEventRedactor redactor,
    ITelemetryPolicyEvaluator policyEvaluator,
    IDurableEventStore queue,
    TimeProvider clock,
    PipelineTelemetry? telemetry = null)
{
    public async Task<ProcessingResult> ProcessAsync(
        string candidateJson,
        CollectorIdentity collector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidateJson);
        long bytesIn = Encoding.UTF8.GetByteCount(candidateJson);
        telemetry?.RecordAttempt(bytesIn);
        return await ProcessCoreAsync(candidateJson, collector, bytesIn, cancellationToken);
    }

    /// <summary>
    /// Records the selection outcome once it is final: before any privacy alert enqueue, so
    /// an alert refused for capacity never hides an event that was already decided or queued.
    /// </summary>
    private ProcessingResult Decided(ProcessingResult result, long bytesIn)
    {
        telemetry?.Record(result, bytesIn);
        return result;
    }

    /// <summary>
    /// Closes ended suppression windows and queues one policy-approved summary for each
    /// window that suppressed events. A summary the policy set does not accept aborts the
    /// close, so suppressed counts are never discarded.
    /// </summary>
    public Task<int> CloseSuppressionWindowsAsync(
        CollectorIdentity collector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(collector);
        DateTimeOffset now = clock.GetUtcNow();
        return queue.CloseExpiredSuppressionWindowsAsync(
            now,
            window =>
            {
                SecurityEventEnvelope summary = Suppression.CreateSummary(window, collector, now);
                PolicyDecision decision = policyEvaluator.Evaluate(summary);
                if (decision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
                {
                    throw new SuppressionSummaryRejectedException(decision.PolicyId, decision.Action);
                }

                SecurityEventEnvelope arranged = summary with
                {
                    Security = new SecurityDecisionContext
                    {
                        PolicyId = decision.PolicyId,
                        PolicyVersion = decision.PolicyVersion,
                        PolicyHash = decision.PolicyHash,
                        ValueScore = decision.Score,
                        Decision = DecisionAction.Aggregate,
                        ClassificationReasons = decision.Reasons
                    }
                };
                return new QueuedEvent(
                    arranged.EventId,
                    EventFingerprint.Create(arranged),
                    JsonSerializer.Serialize(arranged, BowerJson.Envelope),
                    now);
            },
            cancellationToken);
    }

    private async Task<ProcessingResult> ProcessCoreAsync(
        string candidateJson,
        CollectorIdentity collector,
        long bytesIn,
        CancellationToken cancellationToken)
    {
        RedactionResult redaction;
        try
        {
            redaction = redactor.Redact(candidateJson);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Redaction failure is a security failure: quarantine without persisting.
            return Decided(
                ProcessingResult.Failed(DecisionAction.Quarantine, "redaction-failed", ProcessingStage.Redaction),
                bytesIn);
        }

        if (!redaction.Succeeded || redaction.RedactedJson is null)
        {
            return Decided(
                ProcessingResult.Failed(
                    DecisionAction.Quarantine,
                    redaction.FailureCode ?? "redaction-failed",
                    ProcessingStage.Redaction),
                bytesIn);
        }

        SecurityEventEnvelope? candidate;
        try
        {
            candidate = JsonSerializer.Deserialize(redaction.RedactedJson, BowerJson.Envelope);
        }
        catch (JsonException)
        {
            return Decided(
                ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid", ProcessingStage.Schema),
                bytesIn);
        }

        if (candidate is null)
        {
            return Decided(
                ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid", ProcessingStage.Schema),
                bytesIn);
        }

        DateTimeOffset now = clock.GetUtcNow();
        List<string> validationFailures = Validate(candidate, now);
        if (validationFailures.Count > 0)
        {
            ProcessingResult quarantined = Decided(
                new ProcessingResult(
                    DecisionAction.Quarantine,
                    candidate.EventId,
                    false,
                    false,
                    validationFailures,
                    null,
                    null,
                    ProcessingStage.Validation),
                bytesIn);
            // Still notify SOC when high-risk secrets/PII were present in invalid payloads.
            string? alertId = await TryEnqueuePrivacyAlertAsync(
                candidate,
                redaction,
                collector,
                bytesIn,
                cancellationToken);

            return quarantined with { PrivacyAlertEventId = alertId };
        }

        PolicyDecision decision = policyEvaluator.Evaluate(candidate);
        if (decision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            ProcessingResult rejected = Decided(
                new ProcessingResult(
                    decision.Action,
                    candidate.EventId,
                    false,
                    false,
                    decision.Reasons.Concat(decision.Warnings).ToArray(),
                    decision),
                bytesIn);
            string? rejectedAlertId = await TryEnqueuePrivacyAlertAsync(
                candidate,
                redaction,
                collector,
                bytesIn,
                cancellationToken);

            return rejected with { PrivacyAlertEventId = rejectedAlertId };
        }

        SecurityEventEnvelope arranged = candidate with
        {
            TimeObserved = candidate.TimeObserved ?? now,
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
                ReceivedAt = now
            }
        };

        string payload = JsonSerializer.Serialize(arranged, BowerJson.Envelope);
        QueuedEvent queued = new(
            arranged.EventId,
            EventFingerprint.Create(arranged),
            payload,
            now,
            Suppression: decision.Suppression is { } directive
                ? Suppression.CreateRequest(arranged, decision, directive)
                : null);
        EnqueueResult enqueue;
        try
        {
            enqueue = await queue.EnqueueAsync(queued, cancellationToken);
        }
        catch (EventIdentityConflictException)
        {
            return Decided(
                new ProcessingResult(DecisionAction.Quarantine, arranged.EventId, false, false,
                    ["event-identity-conflict"], decision),
                bytesIn);
        }
        catch (QueueCapacityExceededException)
        {
            // Nothing was committed for this attempt.
            telemetry?.RecordCapacityRefusal(bytesIn);
            throw;
        }

        // The event is committed (or deduplicated or suppressed): record it before the alert.
        ProcessingResult committed = Decided(
            new ProcessingResult(
                arranged.Security.Decision,
                arranged.EventId,
                enqueue.Enqueued,
                enqueue.Duplicate,
                [],
                decision,
                null,
                ProcessingStage.Policy,
                enqueue.Suppressed,
                enqueue.Enqueued ? Encoding.UTF8.GetByteCount(payload) : 0,
                new SourceKey(arranged.Application.Name, arranged.Application.Environment)),
            bytesIn);
        string? privacyAlertEventId = await TryEnqueuePrivacyAlertAsync(
            arranged,
            redaction,
            collector,
            bytesIn,
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

        if (enqueue.Suppressed)
        {
            reasons.Add("Suppressed: window allowance reached; counted in a summary event");
        }

        return committed with { Reasons = reasons, PrivacyAlertEventId = privacyAlertEventId };
    }

    private async Task<string?> TryEnqueuePrivacyAlertAsync(
        SecurityEventEnvelope source,
        RedactionResult redaction,
        CollectorIdentity collector,
        long bytesIn,
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
        DateTimeOffset now = clock.GetUtcNow();
        // Idempotent: the alert id and time derive from the source event and detector set,
        // so client retries of the same event collapse onto one alert in the queue.
        string detectorFingerprint = string.Join(',', alertWorthy);
        string alertEventId = CreateAlertEventId(source.EventId, detectorFingerprint);
        DateTimeOffset alertTime = IsWithinAcceptedWindow(source.TimeGenerated, now)
            ? source.TimeGenerated
            : now;
        SecurityEventEnvelope alert = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = alertEventId,
            EventOriginalId = TruncateId($"{source.EventId}:{detectorFingerprint}"),
            TimeGenerated = alertTime,
            TimeObserved = alertTime,
            EventCategory = SecurityEventCategories.PrivacyControl,
            EventType = SecurityEventTypes.SensitiveDataDetected,
            EventAction = "privacy.control.applied",
            EventResult = EventResult.Success,
            EventSeverity = severity,
            EventOutcomeReason =
                $"Privacy engine applied controls for {alertWorthy.Count} high-risk finding(s)",
            // An invalid source can arrive with "application": null (System.Text.Json binds
            // it despite `required`). The alert then carries an empty application, exactly
            // as when the producer sends empty names, and the alert policy decides as usual.
            Application = source.Application ?? MissingApplication,
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

        string payload = JsonSerializer.Serialize(arrangedAlert, BowerJson.Envelope);
        QueuedEvent queued = new(
            arrangedAlert.EventId,
            EventFingerprint.Create(arrangedAlert),
            payload,
            now);
        EnqueueResult enqueue;
        try
        {
            enqueue = await queue.EnqueueAsync(queued, cancellationToken);
        }
        catch (QueueCapacityExceededException)
        {
            // The source outcome is already recorded (and the source event may be queued).
            telemetry?.RecordPrivacyAlertRefusal(bytesIn);
            throw;
        }

        return enqueue.Enqueued || enqueue.Duplicate ? arrangedAlert.EventId : null;
    }

    private static readonly ApplicationContext MissingApplication = new()
    {
        Name = string.Empty,
        Environment = string.Empty
    };

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

    private static string CreateAlertEventId(string? sourceEventId, string detectorFingerprint)
    {
        byte[] digest = SHA256.HashData(
            Encoding.UTF8.GetBytes($"{sourceEventId}\u001f{detectorFingerprint}"));
        return $"privacy-{Convert.ToHexStringLower(digest)[..32]}";
    }

    private static bool IsWithinAcceptedWindow(DateTimeOffset value, DateTimeOffset now) =>
        value != default && value <= now.AddMinutes(5) && value >= now.AddYears(-5);

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

        if (!IsWithinAcceptedWindow(candidate.TimeGenerated, now))
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

/// <param name="Stage">Pipeline stage that decided the event.</param>
/// <param name="Suppressed">Accepted but counted instead of queued (window allowance spent).</param>
/// <param name="QueuedBytes">Payload bytes queued for this event; 0 when nothing was queued.</param>
/// <param name="Source">Application and environment of an accepted event.</param>
public sealed record ProcessingResult(
    DecisionAction Action,
    string? EventId,
    bool Queued,
    bool Duplicate,
    IReadOnlyList<string> Reasons,
    PolicyDecision? PolicyDecision,
    string? PrivacyAlertEventId = null,
    ProcessingStage Stage = ProcessingStage.Policy,
    bool Suppressed = false,
    long QueuedBytes = 0,
    SourceKey? Source = null)
{
    public static ProcessingResult Failed(DecisionAction action, string reason) =>
        Failed(action, reason, ProcessingStage.Policy);

    public static ProcessingResult Failed(DecisionAction action, string reason, ProcessingStage stage)
    {
        return new ProcessingResult(action, null, false, false, [reason], null, Stage: stage);
    }
}

public enum ProcessingStage
{
    Redaction,
    Schema,
    Validation,
    Policy,

    /// <summary>A signed pack transform failed before redaction; nothing was persisted.</summary>
    Transform
}

public sealed record SourceKey(string Application, string Environment);

public sealed class SuppressionSummaryRejectedException(string policyId, DecisionAction action)
    : InvalidOperationException($"Suppression summary was not accepted ({policyId}: {action}); windows stay open.");
