using Bower.Contracts;

namespace Bower.Abstractions;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public interface IEventRedactor
{
    RedactionResult Redact(string json);
}

public sealed record RedactionResult(
    bool Succeeded,
    string? RedactedJson,
    IReadOnlyList<string> RemovedPaths,
    IReadOnlyList<string> MaskedPaths,
    string? FailureCode,
    /// <summary>
    /// Detector ids observed during privacy scan (e.g. <c>au.tfn</c>, <c>secret.jwt</c>).
    /// Never contains original sensitive values.
    /// </summary>
    IReadOnlyList<string>? PrivacyDetected = null,
    /// <summary>
    /// Per-detector action labels applied during privacy scan (e.g. Removed, SHA256).
    /// Never contains original sensitive values.
    /// </summary>
    IReadOnlyDictionary<string, string>? PrivacyActions = null);

public interface ITelemetryPolicyEvaluator
{
    PolicyDecision Evaluate(SecurityEventEnvelope candidate);
}

public sealed record PolicyDecision(
    DecisionAction Action,
    string PolicyId,
    string PolicyVersion,
    string PolicyHash,
    int Score,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> Warnings);

public interface IDurableEventStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<EnqueueResult> EnqueueAsync(
        QueuedEvent candidate,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<QueuedEvent>> LeaseAsync(
        int maximumCount,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default);

    Task MarkDeliveredAsync(
        string eventId,
        string acknowledgement,
        CancellationToken cancellationToken = default);

    Task MarkRetryingAsync(
        string eventId,
        string failureCode,
        DateTimeOffset retryAfter,
        CancellationToken cancellationToken = default);

    Task MarkDeadLetteredAsync(
        string eventId,
        string failureCode,
        CancellationToken cancellationToken = default);

    Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);
}

public sealed record QueuedEvent(
    string EventId,
    string Fingerprint,
    string Payload,
    DateTimeOffset ReceivedAt,
    QueueState State = QueueState.Queued,
    int DeliveryAttempts = 0);

public sealed record EnqueueResult(bool Enqueued, bool Duplicate, string EventId);

public sealed record QueueSnapshot(
    long Queued,
    long Retrying,
    long Uploading,
    long Delivered,
    long DeadLettered,
    long TotalBytes,
    DateTimeOffset? OldestUndelivered);

public enum QueueState
{
    Queued,
    Uploading,
    Retrying,
    Delivered,
    DeadLettered
}

public interface IOutputAdapter
{
    string Id { get; }

    Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default);
}

public sealed record DeliveryResult(
    IReadOnlyList<string> AcknowledgedEventIds,
    IReadOnlyList<DeliveryFailure> Failures,
    string? DestinationAcknowledgement);

public sealed record DeliveryFailure(
    string EventId,
    string Code,
    bool IsRetryable,
    DateTimeOffset? RetryAfter);
