using Bower.Contracts;

namespace Bower.Abstractions;

public interface IEventRedactor
{
    RedactionResult Redact(string json);

    /// <summary>
    /// Redacts an event that carries values Bower computed itself (see
    /// <see cref="RedactionContext"/>), which then skip content detectors: they are digests,
    /// not source text, and masking them breaks event identity. Every other value is scanned.
    /// A redactor without the exemption scans
    /// everything, which is always safe.
    /// </summary>
    RedactionResult Redact(string json, RedactionContext context) => Redact(json);
}

/// <summary>
/// Values in one candidate that Bower generated, so content detectors cannot mistake them
/// for personal data or secrets. Only Bower code that built the values may set them;
/// producer-supplied events always use <see cref="None"/>. This public in-process
/// API is not a security boundary against arbitrary code in the collector process:
/// only collector-owned source code may provide a generated ID. Passing a value
/// supplied by an untrusted producer bypasses its value-detector checks.
/// </summary>
/// <param name="GeneratedEventId">
/// The record id an in-process source computed (<see cref="GeneratedEventIds.FromSourceRecord"/>).
/// Exempts the root <c>eventId</c>/<c>eventOriginalId</c> only while they still equal it,
/// and only when it is <see cref="GeneratedEventIds.IsWellFormed">well-formed</see>.
/// </param>
public sealed record RedactionContext(string? GeneratedEventId = null)
{
    public static RedactionContext None { get; } = new();
}

/// <summary>
/// Event identifiers that Bower's in-process sources compute (<c>syslog-</c> and
/// <c>winevt-</c> record ids): a lowercase prefix, a hyphen and 32 lowercase hex
/// characters of a SHA-256 digest. Collector canaries use <c>bower-canary-</c>
/// followed by 32 lowercase hexadecimal UUID characters. These carry no source text.
/// </summary>
public static class GeneratedEventIds
{
    public const int DigestLength = 32;

    public static bool IsWellFormed(string? value)
    {
        bool canary = value?.StartsWith("bower-canary-", StringComparison.Ordinal) == true;
        int hyphen = canary ? "bower-canary".Length : value?.IndexOf('-', StringComparison.Ordinal) ?? -1;
        if (hyphen is < 1 or > 16 || value!.Length != hyphen + 1 + DigestLength)
        {
            return false;
        }

        for (int index = 0; index < value.Length; index++)
        {
            char c = value[index];
            bool valid = index < hyphen ? canary ? c is >= 'a' and <= 'z' or '-' : c is >= 'a' and <= 'z'
                : index == hyphen || c is >= '0' and <= '9' or >= 'a' and <= 'f';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The id an in-process source wrote for its record, or null. <c>SyslogRecord.Build</c>
    /// and <c>WindowsEventRecord.Build</c> (and the Rust syslog source) write it first,
    /// without whitespace, so only that exact prefix counts. Call only for records Bower's
    /// own sources built: a producer-supplied record is source data, never a generated id.
    /// </summary>
    public static string? FromSourceRecord(string record)
    {
        ArgumentNullException.ThrowIfNull(record);
        const string Prefix = "{\"id\":\"";
        if (!record.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        ReadOnlySpan<char> rest = record.AsSpan(Prefix.Length);
        int end = rest[..Math.Min(rest.Length, 64)].IndexOf('"');
        string? id = end < 0 ? null : rest[..end].ToString();
        return IsWellFormed(id) ? id : null;
    }
}

/// <summary>Failure origin; unknown remains retryable to avoid losing events.</summary>
public enum RedactionFailureOrigin { Unknown, InvalidInput, Operational }

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
    IReadOnlyDictionary<string, string>? PrivacyActions = null,
    RedactionFailureOrigin FailureOrigin = RedactionFailureOrigin.Unknown);

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
    IReadOnlyList<string> Warnings,
    SuppressionDirective? Suppression = null);

/// <summary>Suppression key resolved for one accepted event from its policy.</summary>
public sealed record SuppressionDirective(
    IReadOnlyList<string> KeyFields,
    IReadOnlyList<string> KeyValues,
    int WindowSeconds,
    int AllowPerWindow);

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
        string? leaseToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks every listed event that is still leased (uploading) as delivered, atomically.
    /// Events no longer leased (for example reclaimed after lease expiry) are left untouched
    /// and returned so the caller can report them.
    /// </summary>
    Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(
        IReadOnlyList<string> eventIds,
        string acknowledgement,
        IReadOnlyDictionary<string, string>? leaseTokens,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// As <see cref="MarkDeliveredBatchAsync(IReadOnlyList{string}, string, IReadOnlyDictionary{string, string}?, CancellationToken)"/>,
    /// but each event records its own acknowledgement (for example the S3 object holding it),
    /// still in one atomic transaction: on error nothing is settled. Stores that cannot
    /// settle atomically do not implement it, and the delivery then retries after lease expiry.
    /// </summary>
    Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(
        IReadOnlyList<DeliverySettlement> deliveries,
        IReadOnlyDictionary<string, string>? leaseTokens,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("This store cannot settle per-event acknowledgements atomically.");

    Task MarkRetryingAsync(
        string eventId,
        string failureCode,
        DateTimeOffset retryAfter,
        string? leaseToken,
        CancellationToken cancellationToken = default);

    Task MarkDeadLetteredAsync(
        string eventId,
        string failureCode,
        string? leaseToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Settles failed deliveries atomically: every listed event that is still leased
    /// (uploading) becomes retrying (<see cref="FailureSettlement.RetryAfter"/> set) or
    /// dead-lettered (<see cref="FailureSettlement.RetryAfter"/> null). Events no longer
    /// leased are left untouched and returned. On error nothing is settled.
    /// </summary>
    Task<IReadOnlyList<string>> MarkFailedBatchAsync(
        IReadOnlyList<FailureSettlement> failures,
        CancellationToken cancellationToken = default);

    Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Permanently removes acknowledged (delivered) events whose acknowledgement is older
    /// than <paramref name="deliveredBefore"/>. Never removes undelivered events.
    /// </summary>
    Task<int> PurgeDeliveredAsync(
        DateTimeOffset deliveredBefore,
        int maximumCount,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// As <see cref="PurgeDeliveredAsync(DateTimeOffset, int, CancellationToken)"/>, but only
    /// events whose ledger sequence is at or below <paramref name="archivedThroughSequence"/>
    /// are eligible, so nothing is purged before the archive holds it.
    /// </summary>
    Task<int> PurgeDeliveredAsync(
        DateTimeOffset deliveredBefore,
        int maximumCount,
        long archivedThroughSequence,
        CancellationToken cancellationToken = default);

    /// <summary>Checkpoints and optimises storage. Never changes event state.</summary>
    Task MaintainAsync(CancellationToken cancellationToken = default);

    /// <summary>Dead-lettered events, metadata only (never payloads).</summary>
    Task<IReadOnlyList<DeadLetterRecord>> ListDeadLetteredAsync(
        int maximumCount,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns dead-lettered events to the queue for another delivery attempt. Filters by
    /// failure code prefix and/or event ids; with neither, nothing is replayed.
    /// </summary>
    Task<int> ReplayDeadLetteredAsync(
        string? failureCodePrefix,
        IReadOnlyCollection<string>? eventIds,
        int maximumCount,
        CancellationToken cancellationToken = default);

    /// <summary>Current tamper-evidence ledger head (sequence and chain hash).</summary>
    Task<LedgerHead> GetLedgerHeadAsync(CancellationToken cancellationToken = default);

    /// <summary>Recomputes the ledger chain and compares it with stored events.</summary>
    Task<LedgerVerification> VerifyLedgerAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Closes every suppression window that ended at or before <paramref name="now"/>. A
    /// window that suppressed events is replaced, in the same transaction, by the summary
    /// event <paramref name="createSummary"/> builds; if that throws nothing is closed.
    /// </summary>
    Task<int> CloseExpiredSuppressionWindowsAsync(
        DateTimeOffset now,
        Func<SuppressionWindow, QueuedEvent> createSummary,
        CancellationToken cancellationToken = default);

    /// <summary>Last accepted event per application and environment.</summary>
    Task<IReadOnlyList<SourceActivity>> GetSourceActivityAsync(CancellationToken cancellationToken = default);

    /// <summary>Merges observations: keeps the later time and the larger count per source.</summary>
    Task UpsertSourceActivityAsync(
        IReadOnlyCollection<SourceActivity> activity,
        CancellationToken cancellationToken = default);

    /// <summary>Stored monitoring start per application and environment. Reads only.</summary>
    Task<IReadOnlyList<SourceMonitoring>> GetSourceMonitoringAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Makes <paramref name="expected"/> the monitored set. A source already monitored keeps
    /// its stored start unless the proposed start is earlier (a start stored while the clock
    /// ran ahead); a new one starts at its proposed time; a source no longer expected is
    /// forgotten, so expecting it again starts afresh. Returns the stored starts.
    /// </summary>
    Task<IReadOnlyList<SourceMonitoring>> StartSourceMonitoringAsync(
        IReadOnlyCollection<SourceMonitoring> expected,
        CancellationToken cancellationToken = default);
}

/// <summary>Application and environment that produced an accepted event.</summary>
public sealed record SourceActivity(
    string Application,
    string Environment,
    DateTimeOffset LastSeenAt,
    long EventCount);

/// <summary>
/// When the collector began expecting an application and environment. The silence
/// allowance of a source never seen runs from here, independent of process start.
/// </summary>
public sealed record SourceMonitoring(
    string Application,
    string Environment,
    DateTimeOffset MonitoringSince);

/// <summary>
/// Admission request for an event accepted by a suppressing policy. Key values come from the
/// redacted envelope and are stored until the window closes.
/// </summary>
public sealed record SuppressionRequest(
    string PolicyId,
    string PolicyVersion,
    string PolicyHash,
    string KeyHash,
    IReadOnlyList<string> KeyFields,
    IReadOnlyList<string> KeyValues,
    int WindowSeconds,
    int AllowPerWindow,
    string EventCategory,
    string EventType,
    string Application,
    string Environment,
    string? TenantId);

public sealed record SuppressionWindow(
    SuppressionRequest Rule,
    DateTimeOffset WindowStart,
    DateTimeOffset WindowEnd,
    long Admitted,
    long Suppressed,
    DateTimeOffset? FirstSuppressedAt,
    DateTimeOffset? LastSuppressedAt);

/// <summary>One delivered event and the acknowledgement it records.</summary>
public sealed record DeliverySettlement(string EventId, string Acknowledgement);

/// <summary>
/// One failed delivery to settle. A <see cref="RetryAfter"/> value schedules a retry;
/// null dead-letters the event with <see cref="FailureCode"/>.
/// </summary>
public sealed record FailureSettlement(
    string EventId,
    string FailureCode,
    DateTimeOffset? RetryAfter,
    string? LeaseToken = null);

public sealed record DeadLetterRecord(
    string EventId,
    string? FailureCode,
    int DeliveryAttempts,
    DateTimeOffset ReceivedAt);

public sealed record LedgerHead(long Sequence, string Hash);

public sealed record LedgerIssue(long Sequence, string EventId, string Code, string Detail);

public sealed record LedgerVerification(
    bool Intact,
    long Entries,
    long HeadSequence,
    string HeadHash,
    IReadOnlyList<LedgerIssue> Issues);

public sealed record QueuedEvent(
    string EventId,
    string Fingerprint,
    string Payload,
    DateTimeOffset ReceivedAt,
    QueueState State = QueueState.Queued,
    int DeliveryAttempts = 0,
    string? LeaseToken = null,
    SuppressionRequest? Suppression = null)
{
    /// <summary>
    /// The collector's own periodic health record: it may use the queue's settlement reserve
    /// and is not refused by the free-space critical watermark, so storage alerts still see
    /// a full or critical queue. Set only by collector code, never from submitted input.
    /// </summary>
    public bool UsesStorageReserve { get; init; }
}

public sealed record EnqueueResult(bool Enqueued, bool Duplicate, string EventId, bool Suppressed = false);

public sealed record QueueSnapshot(
    long Queued,
    long Retrying,
    long Uploading,
    long Delivered,
    long DeadLettered,
    long TotalBytes,
    DateTimeOffset? OldestUndelivered,
    long UndeliveredBytes = 0);

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

/// <summary>Implemented by outputs that adapt request concurrency; read by status.</summary>
public interface IOutputConcurrencyStatus
{
    /// <summary>Null when the output keeps no output-wide controller.</summary>
    OutputConcurrencySnapshot? GetConcurrencySnapshot();
}

/// <summary>
/// Adaptive request concurrency of one output stream: current limit and bounds, requests
/// in flight, latency EWMA and counters since start. Metadata only. Process-local: it
/// resets on restart. <see cref="ProcessLocalPausedUntil"/> is this process's last
/// Retry-After deadline; across restarts the queue's durable destination circuit holds
/// the stream.
/// </summary>
public sealed record OutputConcurrencySnapshot(
    string OutputId,
    int Limit,
    int MinimumLimit,
    int MaximumLimit,
    int InFlight,
    long? LatencyEwmaMilliseconds,
    long Requests,
    long Throttles,
    long ServerErrors,
    long Timeouts,
    long LatencySpikes,
    long Decreases,
    long Increases,
    long Pauses,
    DateTimeOffset? ProcessLocalPausedUntil);

public sealed record DeliveryResult(
    IReadOnlyList<string> AcknowledgedEventIds,
    IReadOnlyList<DeliveryFailure> Failures,
    string? DestinationAcknowledgement)
{
    /// <summary>
    /// Optional per-event acknowledgement (for example the S3 object holding the event).
    /// Overrides <see cref="DestinationAcknowledgement"/> for the events it lists.
    /// </summary>
    public IReadOnlyDictionary<string, string>? EventAcknowledgements { get; init; }
}

public sealed record DeliveryFailure(
    string EventId,
    string Code,
    bool IsRetryable,
    DateTimeOffset? RetryAfter)
{
    /// <summary>Destination-wide faults preserve records and do not spend poison budgets.
    /// The reserved prefix is persisted with the retry deadline for restart-safe circuits.</summary>
    public bool IsDestinationFailure => Code.StartsWith("destination-", StringComparison.Ordinal);
}
