using Bower.Abstractions;

namespace Bower.Functions.Collector;

/// <summary>
/// Holds the arranged events of exactly one request (the event and, at most, its privacy
/// alert) so the unchanged <see cref="Bower.Core.SecurityEventProcessor"/> can run without a
/// durable queue. It is created per request, never shared, never written to disk and dropped
/// when the response is sent, whether or not delivery succeeded. Only enqueue is supported:
/// every queue, lease and ledger operation throws because this host has none.
/// </summary>
public sealed class RequestEventBuffer : IDurableEventStore
{
    /// <summary>The processor stages one event plus one privacy alert; anything more is a bug.</summary>
    public const int MaximumEvents = 4;

    private readonly List<QueuedEvent> events = [];

    public IReadOnlyList<QueuedEvent> Events => events;

    public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<EnqueueResult> EnqueueAsync(QueuedEvent candidate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();
        QueuedEvent? existing = events.Find(item => string.Equals(item.EventId, candidate.EventId, StringComparison.Ordinal));
        if (existing is not null)
        {
            return Task.FromResult(new EnqueueResult(false, true, existing.EventId));
        }

        if (events.Count >= MaximumEvents)
        {
            throw new InvalidOperationException("A single request staged more events than allowed.");
        }

        events.Add(candidate);
        return Task.FromResult(new EnqueueResult(true, false, candidate.EventId));
    }

    public Task<IReadOnlyList<QueuedEvent>> LeaseAsync(int maximumCount, TimeSpan leaseDuration, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task MarkDeliveredAsync(string eventId, string acknowledgement, string? leaseToken, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(IReadOnlyList<string> eventIds, string acknowledgement,
        IReadOnlyDictionary<string, string>? leaseTokens, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task MarkRetryingAsync(string eventId, string failureCode, DateTimeOffset retryAfter, string? leaseToken,
        CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task MarkDeadLetteredAsync(string eventId, string failureCode, string? leaseToken, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task<IReadOnlyList<string>> MarkFailedBatchAsync(IReadOnlyList<FailureSettlement> failures, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) => throw Unsupported();

    public Task<int> PurgeDeliveredAsync(DateTimeOffset deliveredBefore, int maximumCount, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task MaintainAsync(CancellationToken cancellationToken = default) => throw Unsupported();

    public Task<IReadOnlyList<DeadLetterRecord>> ListDeadLetteredAsync(int maximumCount, CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task<int> ReplayDeadLetteredAsync(string? failureCodePrefix, IReadOnlyCollection<string>? eventIds, int maximumCount,
        CancellationToken cancellationToken = default) =>
        throw Unsupported();

    public Task<LedgerHead> GetLedgerHeadAsync(CancellationToken cancellationToken = default) => throw Unsupported();

    public Task<LedgerVerification> VerifyLedgerAsync(CancellationToken cancellationToken = default) => throw Unsupported();

    private static NotSupportedException Unsupported() =>
        new("The Azure Functions collector has no durable queue or ledger.");
}
