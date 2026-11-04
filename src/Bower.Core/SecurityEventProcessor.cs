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
    PipelineTelemetry? telemetry = null,
    EventTap? tap = null)
{
    public Task<ProcessingResult> ProcessAsync(
        string candidateJson,
        CollectorIdentity collector,
        CancellationToken cancellationToken = default) =>
        ProcessAsync(candidateJson, collector, RedactionContext.None, cancellationToken);

    /// <summary>
    /// As <see cref="ProcessAsync(string, CollectorIdentity, CancellationToken)"/> for a
    /// candidate that carries Bower-generated values: <paramref name="context"/> keeps them out
    /// of content detectors (see <see cref="RedactionContext"/>). Never describe
    /// producer-supplied values with it.
    /// </summary>
    public async Task<ProcessingResult> ProcessAsync(
        string candidateJson,
        CollectorIdentity collector,
        RedactionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidateJson);
        long bytesIn = Encoding.UTF8.GetByteCount(candidateJson);
        // Attempts include retries and failures, even if a surrounding batch rolls back.
        telemetry?.RecordAttempt(bytesIn);
        int? pendingBefore = QueueEnqueueBatch.PendingCount(queue);
        bool sourceRecord = QueueEnqueueBatch.IsSourceRecord(queue);
        ProcessingResult result;
        try
        {
            result = await ProcessCoreAsync(candidateJson, collector, context, bytesIn, false, cancellationToken);
        }
        catch (QueueCapacityExceededException)
        {
            // For an atomic source record, an alert refusal rolls back the main write too.
            // The primary refusal was already recorded as an alert refusal.
            if (QueueEnqueueBatch.SourceRecordMutated(queue))
            {
                telemetry?.RecordSourceRecordRollback(bytesIn);
            }
            throw;
        }
        if (result.Queued || result.Suppressed)
        {
            // A batched enqueue is provisional until commit. Report each rolled-back
            // candidate as a refusal if SQLite rejects that commit for capacity.
            QueueEnqueueBatch.WhenRefused(queue, refusal =>
            {
                telemetry?.RecordCapacityRefusal(bytesIn, refusal.Reason);
                if (sourceRecord) telemetry?.RecordSourceRecordRollback(bytesIn);
            });
        }
        else if (result.PrivacyAlertEventId is not null && pendingBefore is { } before
            && QueueEnqueueBatch.PendingCount(queue) > before)
        {
            // Only the generated alert was newly written. Do not classify it as a main
            // event refusal or count it twice if the alert was already a duplicate.
            QueueEnqueueBatch.WhenRefused(queue, refusal =>
            {
                telemetry?.RecordPrivacyAlertRefusal(bytesIn, refusal.Reason);
                if (sourceRecord) telemetry?.RecordSourceRecordRollback(bytesIn);
            });
        }

        return result;
    }

    // Only the collector assembly's own health worker uses this entry point. Origin is
    // selected by code, never by a property or collector identity in the submitted JSON.
    internal async Task<ProcessingResult> ProcessCollectorHealthAsync(
        string candidateJson,
        CollectorIdentity collector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidateJson);
        long bytesIn = Encoding.UTF8.GetByteCount(candidateJson);
        telemetry?.RecordAttempt(bytesIn);
        return await ProcessCoreAsync(candidateJson, collector, RedactionContext.None, bytesIn, true, cancellationToken);
    }

    /// <summary>
    /// Runs <paramref name="action"/> now, or, inside a source's group commit
    /// (<see cref="QueueEnqueueBatch"/>), once that commit succeeds; a rolled-back read is
    /// read again, so its signals must not be recorded twice.
    /// </summary>
    internal void WhenDurable(Action action) => QueueEnqueueBatch.WhenDurable(queue, action);

    /// <summary>
    /// Records the selection outcome once it is final: before any privacy alert enqueue, so
    /// an alert refused for capacity never hides an event that was already decided or queued.
    /// The tap sees the same outcome, after redaction only: <paramref name="subject"/> is the
    /// redacted candidate and <paramref name="acceptedPayload"/> the redacted queued payload.
    /// </summary>
    private ProcessingResult Decided(
        ProcessingResult result,
        long bytesIn,
        SecurityEventEnvelope? subject = null,
        string? acceptedPayload = null)
    {
        void RecordOutcome()
        {
            telemetry?.Record(result, bytesIn);
            tap?.Publish(result, subject, acceptedPayload);
        }
        if (result.RedactionRetryRequired)
        {
            // This is an attempt-level failure, not a claim that the source record was
            // handled. The source rolls its record back and retries, but operators still
            // need the failure signal and redacted tap frame for each attempt.
            RecordOutcome();
        }
        else
        {
            WhenDurable(RecordOutcome);
        }
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

    /// <summary>Quarantine reason for an archive replay sent to a collector with another id.</summary>
    public const string ArchiveReplayCollectorMismatch = "archive-replay-collector-mismatch";

    /// <summary>
    /// Sentinel identifies an event by the collector-stamped <c>(CollectorId, EventId)</c>.
    /// <c>bower archive replay</c> labels each event with the collector that first accepted it;
    /// replayed through a collector with another id it would land as a second, different
    /// event, so it is refused. Labels only refuse here: they never set the identity.
    /// The labels are read from the candidate <b>before</b> redaction (and kept only in
    /// memory): a privacy rule may remove labels, or a detector may mask a collector id
    /// inside one, and neither may change the replay check.
    /// </summary>
    internal static bool IsArchiveReplayFromAnotherCollector(string? replayOrigin, CollectorIdentity collector) =>
        replayOrigin is not null && !string.Equals(replayOrigin, collector.Id, StringComparison.Ordinal);

    /// <summary>
    /// The unredacted <c>labels.bowerReplayCollectorId</c> of an archive replay
    /// (<c>labels.bowerReplay == "archive"</c>), or null. Bounded like the identity check;
    /// a candidate that does not parse is left to redaction, which refuses it.
    /// </summary>
    internal static string? ArchiveReplayOrigin(string candidateJson)
    {
        if (Encoding.UTF8.GetByteCount(candidateJson) > RedactedEventIdentity.MaximumDocumentBytes)
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(candidateJson, new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("labels", out JsonElement labels)
                && labels.ValueKind == JsonValueKind.Object
                && labels.TryGetProperty("bowerReplay", out JsonElement replay)
                && replay.ValueKind == JsonValueKind.String && replay.ValueEquals("archive")
                && labels.TryGetProperty("bowerReplayCollectorId", out JsonElement origin)
                && origin.ValueKind == JsonValueKind.String
                    ? origin.GetString()
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task<ProcessingResult> ProcessCoreAsync(
        string candidateJson,
        CollectorIdentity collector,
        RedactionContext context,
        long bytesIn,
        bool internalHealth,
        CancellationToken cancellationToken)
    {
        // Captured before redaction, never persisted; see IsArchiveReplayFromAnotherCollector.
        string? replayOrigin = ArchiveReplayOrigin(candidateJson);
        RedactionResult redaction;
        try
        {
            redaction = redactor.Redact(candidateJson, context);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return RedactionFailure(candidateJson, bytesIn, identityChanged: false);
        }

        if (!redaction.Succeeded || redaction.RedactedJson is null)
        {
            if (!redaction.Succeeded && redaction.FailureOrigin == RedactionFailureOrigin.InvalidInput)
            {
                if (RedactedEventIdentity.Compare(candidateJson, candidateJson) == RedactedEventIdentity.Comparison.InvalidOriginal
                    || !OriginalEnvelopeParses(candidateJson))
                {
                    return Decided(ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid", ProcessingStage.Schema), bytesIn);
                }
                return Decided(ProcessingResult.Failed(DecisionAction.Quarantine, "redaction-invalid-input", ProcessingStage.Redaction), bytesIn);
            }
            return RedactionFailure(candidateJson, bytesIn,
                identityChanged: string.Equals(redaction.FailureCode, ProcessingResult.EventIdRedacted, StringComparison.Ordinal));
        }

        // Check the root ID before deserializing the redacted envelope: a privacy rule may
        // remove it or change its type, making deserialization fail before we can compare it.
        // Only this field is examined in memory; neither value is returned or logged.
        RedactedEventIdentity.Comparison comparison = RedactedEventIdentity.Compare(candidateJson, redaction.RedactedJson);
        if (comparison == RedactedEventIdentity.Comparison.Changed)
        {
            return Decided(ProcessingResult.Failed(DecisionAction.Quarantine, ProcessingResult.EventIdRedacted, ProcessingStage.Redaction), bytesIn);
        }
        if (comparison == RedactedEventIdentity.Comparison.InvalidOriginal)
        {
            return Decided(ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid", ProcessingStage.Schema), bytesIn);
        }

        SecurityEventEnvelope? candidate;
        try
        {
            candidate = JsonSerializer.Deserialize(redaction.RedactedJson, BowerJson.Envelope);
        }
        catch (JsonException)
        {
            // A valid original damaged in a non-ID field by a custom redactor is not a
            // permanent source rejection. Inspect it only in memory and never log it.
            if (OriginalEnvelopeParses(candidateJson))
            {
                return RedactionFailure(candidateJson, bytesIn, identityChanged: false);
            }
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

        if (string.Equals(candidate.EventType, SecurityEventTypes.CollectorHealth, StringComparison.Ordinal) != internalHealth)
        {
            return Decided(
                ProcessingResult.Failed(DecisionAction.Quarantine, "reserved-event-type", ProcessingStage.Validation),
                bytesIn);
        }

        if (IsArchiveReplayFromAnotherCollector(replayOrigin, collector))
        {
            return Decided(
                ProcessingResult.Failed(DecisionAction.Quarantine, ArchiveReplayCollectorMismatch, ProcessingStage.Validation),
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
                bytesIn,
                candidate);
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
                bytesIn,
                candidate);
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
                : null)
        {
            UsesStorageReserve = internalHealth
        };
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
                bytesIn,
                arranged);
        }
        catch (QueueCapacityExceededException exception)
        {
            // Nothing was committed for this attempt.
            telemetry?.RecordCapacityRefusal(bytesIn, exception.Reason);
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
            bytesIn,
            arranged,
            payload);
        if (enqueue.Enqueued)
        {
            // Counted once per stored event: a duplicate or suppressed retry adds nothing.
            WhenDurable(() => telemetry?.RecordRedactions(redaction.PrivacyDetected));
        }

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

    private static bool OriginalEnvelopeParses(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, BowerJson.Envelope) is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private ProcessingResult RedactionFailure(string original, long bytesIn, bool identityChanged)
    {
        if (RedactedEventIdentity.Compare(original, original) == RedactedEventIdentity.Comparison.InvalidOriginal
            || !OriginalEnvelopeParses(original))
        {
            return Decided(ProcessingResult.Failed(DecisionAction.Quarantine, "schema-invalid", ProcessingStage.Schema), bytesIn);
        }
        return Decided(ProcessingResult.Failed(DecisionAction.Quarantine,
            identityChanged ? ProcessingResult.EventIdRedacted : ProcessingResult.RedactionUnavailable,
            ProcessingStage.Redaction), bytesIn);
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
        catch (QueueCapacityExceededException exception)
        {
            // The source outcome is already recorded (and the source event may be queued).
            telemetry?.RecordPrivacyAlertRefusal(bytesIn, exception.Reason);
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
    /// <summary>A retryable identity collision risk; the raw identifier is never exposed.</summary>
    public const string EventIdRedacted = RedactedEventIdentity.RetryReason;

    /// <summary>Redaction or detection could not complete; the record was not persisted.</summary>
    public const string RedactionUnavailable = "redaction-unavailable";

    /// <summary>The caller must retain and retry the source record rather than acknowledge it.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool RedactionRetryRequired => Stage == ProcessingStage.Redaction
        && (Reasons.Contains(EventIdRedacted, StringComparer.Ordinal)
            || Reasons.Contains(RedactionUnavailable, StringComparer.Ordinal));

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
