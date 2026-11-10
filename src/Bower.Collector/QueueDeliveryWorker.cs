using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.Collector;

/// <summary>
/// When the output last acknowledged an event, for the heartbeat, and the most recent
/// failure code (a fixed string such as <c>destination-azure-credential-failed</c>), for
/// status and health records. In memory, so null until the first outcome after start-up;
/// management keeps the last reported time.
/// </summary>
public sealed class DeliveryActivity
{
    private readonly Lock gate = new();
    private long lastTicks;
    private DeliveryFailureActivity? lastFailure;

    /// <summary>The most recent delivery failure since start-up, or null.</summary>
    public DeliveryFailureActivity? LastFailure
    {
        get
        {
            lock (gate)
            {
                return lastFailure;
            }
        }
    }

    public void RecordFailure(string code, DateTimeOffset at)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        lock (gate)
        {
            lastFailure = new DeliveryFailureActivity(code, at);
        }
    }

    public DateTimeOffset? LastSuccessfulDeliveryAt
    {
        get
        {
            long ticks = Interlocked.Read(ref lastTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public void RecordDelivery(DateTimeOffset at) =>
        Interlocked.Exchange(ref lastTicks, at.UtcTicks);
}

/// <summary>A delivery failure code (fixed text, never response or exception content) and when it was settled.</summary>
public sealed record DeliveryFailureActivity(string Code, DateTimeOffset At);

public sealed record QueueDeliveryOptions
{
    public int BatchSize { get; init; } = 500;

    public TimeSpan LeaseDuration { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Cancellation deadline for one output call, leaving time to settle its lease.</summary>
    public TimeSpan DeliveryTimeout { get; init; } = TimeSpan.FromMinutes(4);

    public TimeSpan IdleDelay { get; init; } = TimeSpan.FromSeconds(1);

    public TimeSpan ErrorDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Wait after the queue database was busy (another writer held it past the busy timeout,
    /// for example a retention batch). A back-off, not a loop failure.
    /// </summary>
    public TimeSpan BusyDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// How long the queue database may stay busy before log 1009 is raised from Information
    /// to Warning: a write lock held this long (for example by an external tool with an open
    /// transaction on the queue file) is stalling delivery, not ordinary contention.
    /// </summary>
    public TimeSpan BusyWarningAfter { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Settlement attempts while the queue database is busy, so an acknowledged batch is not redelivered after its lease expires.</summary>
    public int SettlementAttempts { get; init; } = 5;

    /// <summary>Retryable failures dead-letter once an event has been leased this many times.</summary>
    public int MaximumDeliveryAttempts { get; init; } = 20;

    public QueueDeliveryOptions Validate()
    {
        if (LeaseDuration < TimeSpan.FromSeconds(31) || LeaseDuration > TimeSpan.FromHours(1))
        {
            throw new InvalidOperationException("BOWER_DELIVERY_LEASE_SECONDS must be between 31 and 3600.");
        }

        if (DeliveryTimeout < TimeSpan.FromSeconds(1)
            || DeliveryTimeout > LeaseDuration - TimeSpan.FromSeconds(30))
        {
            throw new InvalidOperationException(
                "BOWER_DELIVERY_TIMEOUT_SECONDS must be at least 1 and leave at least 30 seconds before lease expiry.");
        }

        return this;
    }
}

/// <summary>
/// Drains the durable queue into the configured output. Stays a low-latency hosted loop
/// rather than a scheduled job: delivery is continuous and its durability lives in the
/// queue's lease/acknowledgement state, not in a scheduler.
/// </summary>
public sealed partial class QueueDeliveryWorker(
    IDurableEventStore queue,
    IOutputAdapter output,
    TimeProvider clock,
    QueueDeliveryOptions options,
    ILogger<QueueDeliveryWorker> logger,
    DeliveryActivity? activity = null) : BackgroundService
{
    private readonly QueueDeliveryOptions deliveryOptions = options.Validate();

    /// <summary>A persistent loop failure (for example a full volume) is logged once, then once per this many attempts.</summary>
    public const int LoopFailureLogInterval = 12;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        long consecutiveFailures = 0;
        long consecutiveBusy = 0;
        long busySince = 0;
        bool busyEscalated = false;
        bool wasBusy = false;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int leased = await DeliverOnceAsync(stoppingToken);
                consecutiveFailures = 0;
                consecutiveBusy = 0;
                busyEscalated = false;
                wasBusy = false;
                if (leased == 0)
                {
                    await Task.Delay(deliveryOptions.IdleDelay, clock, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (QueueStorageErrors.IsBusy(exception))
            {
                // Busy is contention, not a failure: nothing was written, leased events stay
                // leased, and the next attempt follows a short back-off. Logged at most once
                // per LoopFailureLogInterval busy attempts.
                consecutiveBusy++;
                if (!wasBusy)
                {
                    busySince = clock.GetTimestamp();
                }
                wasBusy = true;

                TimeSpan busyFor = clock.GetElapsedTime(busySince);
                bool escalate = busyFor >= deliveryOptions.BusyWarningAfter;
                if (consecutiveBusy == 1 || consecutiveBusy % LoopFailureLogInterval == 0 || (escalate && !busyEscalated))
                {
                    LogQueueBusy(logger, escalate ? LogLevel.Warning : LogLevel.Information, consecutiveBusy, (long)busyFor.TotalSeconds);
                }

                busyEscalated |= escalate;

                await Task.Delay(deliveryOptions.BusyDelay, clock, stoppingToken);
            }
            catch (Exception exception)
            {
                // Storage errors (for example SQLITE_BUSY or a full volume) must not stop
                // collection. Leased events stay leased and are reclaimed when the lease
                // expires. Bounded logging: a full disk must not also fill the journal.
                // Retain both log counters until a successful iteration. Alternating busy
                // and other failures must not defeat the rate limit for either log. Keep
                // the escalation latch too: subsequent sustained busy intervals are logged
                // as warnings at the periodic interval until the loop succeeds.
                wasBusy = false;
                consecutiveFailures++;
                if (consecutiveFailures == 1 || consecutiveFailures % LoopFailureLogInterval == 0)
                {
                    LogLoopFailure(logger, exception.GetType().Name, consecutiveFailures);
                }

                await Task.Delay(deliveryOptions.ErrorDelay, clock, stoppingToken);
            }
        }
    }

    /// <summary>Leases one batch, delivers it and settles every leased event exactly once.</summary>
    public async Task<int> DeliverOnceAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<QueuedEvent> events = await queue.LeaseAsync(
            deliveryOptions.BatchSize,
            deliveryOptions.LeaseDuration,
            cancellationToken);
        if (events.Count == 0)
        {
            return 0;
        }

        Dictionary<string, QueuedEvent> leased = events.ToDictionary(
            item => item.EventId,
            StringComparer.Ordinal);
        HashSet<string> settled = new(StringComparer.Ordinal);

        DeliveryResult result;
        using CancellationTokenSource deadline = new(deliveryOptions.DeliveryTimeout, clock);
        using CancellationTokenSource attempt = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, deadline.Token);
        try
        {
            // Await cancellation cooperatively: never abandon a still-running adapter and
            // start a second upload from this worker. Settlement uses the host token, not
            // the expired attempt token, so a timed-out batch can be durably retried.
            result = await output.DeliverAsync(events, attempt.Token);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            LogOutputTimeout(logger, output.Id);
            result = new DeliveryResult([], events.Select(item => new DeliveryFailure(
                item.EventId, "destination-output-timeout", IsRetryable: true, RetryAfter: null)).ToArray(), null);
        }
        catch (Exception exception) when (
            exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            LogOutputFailure(logger, output.Id, exception.GetType().Name);
            result = new DeliveryResult(
                [],
                events.Select(item => new DeliveryFailure(
                    item.EventId,
                    "output-adapter-failure",
                    IsRetryable: true,
                    RetryAfter: null)).ToArray(),
                null);
        }

        string acknowledgement = result.DestinationAcknowledgement
            ?? $"adapter:{output.Id}:acknowledged";
        List<string> delivered = new(result.AcknowledgedEventIds.Count);
        foreach (string eventId in result.AcknowledgedEventIds)
        {
            if (!leased.ContainsKey(eventId) || !settled.Add(eventId))
            {
                LogUnexpectedResult(logger, output.Id);
                continue;
            }

            delivered.Add(eventId);
        }

        if (delivered.Count > 0)
        {
            // One queue transaction for every acknowledged event in the batch, also when the
            // adapter names a per-event acknowledgement (one per S3 object, for example): a
            // partial settlement would re-lease later objects' events into different objects.
            Dictionary<string, string> tokens = events.ToDictionary(item => item.EventId, item => item.LeaseToken!, StringComparer.Ordinal);
            IReadOnlyDictionary<string, string>? perEvent = result.EventAcknowledgements;
            IReadOnlyList<string> reclaimed = await SettleAsync(
                token => perEvent is null or { Count: 0 }
                    ? queue.MarkDeliveredBatchAsync(delivered, acknowledgement, tokens, token)
                    : queue.MarkDeliveredBatchAsync(
                        [.. delivered.Select(eventId => new DeliverySettlement(eventId, perEvent.GetValueOrDefault(eventId) ?? acknowledgement))],
                        tokens,
                        token),
                cancellationToken);
            for (int index = 0; index < reclaimed.Count; index++)
            {
                // The lease expired and the event was reclaimed; the newer lease owns it now.
                LogStaleLease(logger, output.Id);
            }

            if (reclaimed.Count < delivered.Count)
            {
                activity?.RecordDelivery(clock.GetUtcNow());
            }
        }

        List<FailureSettlement> failed = [];
        foreach (DeliveryFailure failure in result.Failures)
        {
            if (!leased.TryGetValue(failure.EventId, out QueuedEvent? item) || !settled.Add(failure.EventId))
            {
                LogUnexpectedResult(logger, output.Id);
                continue;
            }

            failed.Add(ToSettlement(item, failure));
        }

        // An adapter that neither acknowledged nor failed an event broke its contract;
        // retry rather than leave the event leased until the lease expires.
        foreach (QueuedEvent item in events.Where(item => !settled.Contains(item.EventId)))
        {
            LogUnexpectedResult(logger, output.Id);
            failed.Add(ToSettlement(
                item,
                new DeliveryFailure(item.EventId, "output-result-missing", true, null)));
        }

        // Output adapters can return free-form failure codes (including from a relay).
        // Only a bounded allow-list reaches logs or health metadata.
        string? lastFailure = null;
        foreach (IGrouping<(string Code, bool Retrying), FailureSettlement> group in failed
            .GroupBy(item => (Code: SafeFailureCode(item.FailureCode), Retrying: item.RetryAfter is not null))
            .OrderBy(group => group.Key.Code, StringComparer.Ordinal))
        {
            LogDeliveryFailures(logger, output.Id, group.Count(), group.Key.Code,
                group.Key.Retrying ? "retrying" : "dead-lettered");
            if (lastFailure is null || IsCredentialFailure(group.Key.Code)) lastFailure = group.Key.Code;
        }
        if (lastFailure is not null) activity?.RecordFailure(lastFailure, clock.GetUtcNow());

        if (failed.Count > 0)
        {
            // One queue transaction for every retrying and dead-lettered event in the batch.
            // On error nothing is settled and the events are redelivered after lease expiry.
            IReadOnlyList<string> reclaimed = await SettleAsync(
                token => queue.MarkFailedBatchAsync(failed, token),
                cancellationToken);
            for (int index = 0; index < reclaimed.Count; index++)
            {
                // The lease expired and the event was reclaimed; the newer lease owns it now.
                LogStaleLease(logger, output.Id);
            }
        }

        return events.Count;
    }

    /// <summary>
    /// One settlement transaction, retried while the queue database is busy. Settlement is
    /// guarded by lease tokens, so a retry after a busy refusal (nothing written) is exact.
    /// </summary>
    private async Task<IReadOnlyList<string>> SettleAsync(
        Func<CancellationToken, Task<IReadOnlyList<string>>> settle,
        CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await settle(cancellationToken);
            }
            catch (Exception exception) when (QueueStorageErrors.IsBusy(exception) && attempt < deliveryOptions.SettlementAttempts)
            {
                await Task.Delay(deliveryOptions.BusyDelay, clock, cancellationToken);
            }
        }
    }

    private static bool IsCredentialFailure(string code) => code is
        "destination-azure-credential-failed" or "destination-azure-http-401" or "destination-azure-http-403"
        or "destination-s3-credential-failed" or "destination-s3-access-denied" or "destination-s3-kms-denied"
        || code.StartsWith("destination-http-401", StringComparison.Ordinal)
        || code.StartsWith("destination-http-403", StringComparison.Ordinal);

    private static string SafeFailureCode(string code) => code switch
    {
        "destination-azure-http-401:retry-after-capped" => "destination-azure-http-401",
        "destination-azure-http-403:retry-after-capped" => "destination-azure-http-403",
        "destination-azure-credential-failed" or "destination-azure-http-401" or "destination-azure-http-403"
            or "payload-invalid-json" or "payload-event-id-mismatch" or "payload-too-large"
            or "destination-output-timeout" or "output-adapter-failure" or "output-result-missing"
            or "destination-syslog-unavailable" => code,
        _ when IsS3Code(code) => code,
        _ when IsHttpOutputCode(Uncapped(code)) => Uncapped(code),
        _ => "delivery-failure"
    };

    private static string Uncapped(string code) => code.EndsWith(":retry-after-capped", StringComparison.Ordinal)
        ? code[..^":retry-after-capped".Length]
        : code;

    private FailureSettlement ToSettlement(QueuedEvent item, DeliveryFailure failure)
    {
        // Adapter codes can be influenced by a relay. Preserve destination/retry
        // classification from the original outcome, but persist only bounded codes.
        string safeCode = SafePersistedFailureCode(failure.Code, failure.IsDestinationFailure);
        if (!failure.IsRetryable)
        {
            return new FailureSettlement(item.EventId, safeCode, null, item.LeaseToken);
        }

        if (!failure.IsDestinationFailure && item.DeliveryAttempts >= deliveryOptions.MaximumDeliveryAttempts)
        {
            LogAttemptsExhausted(logger, output.Id, item.DeliveryAttempts);
            return new FailureSettlement(item.EventId, $"max-attempts-exceeded:{safeCode}", null, item.LeaseToken);
        }

        DateTimeOffset retryAt = clock.GetUtcNow().Add(failure.IsDestinationFailure
            ? TimeSpan.FromSeconds(30)
            : CalculateRetryDelay(item.DeliveryAttempts));
        if (failure.RetryAfter > retryAt) retryAt = failure.RetryAfter.Value;
        DateTimeOffset maximum = clock.GetUtcNow().AddHours(1);
        string code = safeCode;
        if (retryAt > maximum)
        {
            retryAt = maximum;
            code += ":retry-after-capped";
            LogRetryAfterCapped(logger, output.Id);
        }
        return new FailureSettlement(item.EventId, code, retryAt, item.LeaseToken);
    }

    private static string SafePersistedFailureCode(string code, bool destination)
    {
        const string capped = ":retry-after-capped";
        bool hasCap = code.EndsWith(capped, StringComparison.Ordinal);
        string baseCode = hasCap ? code[..^capped.Length] : code;
        string safe = baseCode switch
        {
            "destination-azure-credential-failed" or "destination-azure-paused" or "destination-azure-unavailable"
                or "destination-azure-cancelled" or "destination-output-timeout" or "destination-ama-cancelled"
                or "destination-relay-unavailable" or "destination-relay-response-invalid" or "destination-relay-result-missing"
                or "payload-invalid-json" or "payload-event-id-mismatch" or "payload-too-large"
                or "preflight-record-too-large" or "preflight-field-too-large" or "preflight-type-mismatch"
                or "preflight-time-generated-missing"
                or "output-adapter-failure" or "output-result-missing" or "azure-http-400-isolated"
                or "record-exceeds-ama-file-limit" => baseCode,
            _ when IsS3Code(baseCode) => baseCode,
            _ when IsHttpOutputCode(baseCode) => baseCode,
            _ when IsHttpStatusCode(baseCode, "destination-azure-http-")
                || IsHttpStatusCode(baseCode, "destination-relay-http-")
                || IsHttpStatusCode(baseCode, "relay-http-")
                || IsHttpStatusCode(baseCode, "azure-http-") => baseCode,
            _ when baseCode.StartsWith("relay-rejected:", StringComparison.Ordinal) => "relay-rejected:unknown",
            _ => destination ? "destination-output-failure" : "delivery-failure"
        };
        return hasCap ? safe + capped : safe;
    }

    /// <summary>Bounded S3 output codes (<c>Bower.Output.S3.S3Output</c>).</summary>
    private static bool IsS3Code(string code) => code is
        "destination-s3-throttled" or "destination-s3-access-denied" or "destination-s3-kms-denied"
        or "destination-s3-no-such-bucket" or "destination-s3-wrong-region" or "destination-s3-credential-failed"
        or "destination-s3-unavailable" or "destination-s3-cancelled"
        || IsHttpStatusCode(code, "destination-s3-http-");
    /// <summary>
    /// Codes of the HTTP output (<c>Bower.Output.Http</c>): fixed destination codes, or
    /// <c>[destination-]http-&lt;status&gt;</c> with an optional <c>:hec-&lt;0-99&gt;</c>.
    /// </summary>
    internal static bool IsHttpOutputCode(string code)
    {
        if (code is "destination-http-unavailable" or "destination-http-timeout" or "destination-http-cancelled"
            or "destination-http-response-invalid")
        {
            return true;
        }

        int hec = code.IndexOf(":hec-", StringComparison.Ordinal);
        string status = hec < 0 ? code : code[..hec];
        if (hec >= 0)
        {
            ReadOnlySpan<char> number = code.AsSpan(hec + ":hec-".Length);
            if (number.Length is < 1 or > 2 || !char.IsAsciiDigit(number[0])
                || (number.Length == 2 && (number[0] == '0' || !char.IsAsciiDigit(number[1]))))
            {
                return false;
            }
        }

        return IsHttpStatusCode(status, "destination-http-") || IsHttpStatusCode(status, "http-");
    }

    private static bool IsHttpStatusCode(string code, string prefix)
    {
        if (!code.StartsWith(prefix, StringComparison.Ordinal)) return false;
        ReadOnlySpan<char> status = code.AsSpan(prefix.Length);
        return status.Length == 3 && status[0] is >= '1' and <= '5'
            && status[1] is >= '0' and <= '9' && status[2] is >= '0' and <= '9';
    }

    [LoggerMessage(EventId = 1006, Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} retry deadline exceeded one hour and was capped.")]
    private static partial void LogRetryAfterCapped(ILogger logger, string outputId);

    [LoggerMessage(EventId = 1008, Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} did not deliver {Count} events ({FailureCode}); {Disposition}.")]
    private static partial void LogDeliveryFailures(ILogger logger, string outputId, int count, string failureCode, string disposition);

    [LoggerMessage(EventId = 1007, Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} exceeded its delivery timeout; batch will retry.")]
    private static partial void LogOutputTimeout(ILogger logger, string outputId);

    internal static TimeSpan CalculateRetryDelay(int attempt)
    {
        int exponent = Math.Min(attempt, 8);
        double seconds = Math.Min(300, Math.Pow(2, exponent));
        double jitter = Random.Shared.NextDouble() * Math.Min(10, seconds * 0.2);
        return TimeSpan.FromSeconds(seconds + jitter);
    }

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} failed with {FailureType}; batch will retry.")]
    private static partial void LogOutputFailure(
        ILogger logger,
        string outputId,
        string failureType);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Error,
        Message = "Delivery loop failed with {FailureType} ({ConsecutiveFailures} failures since the last successful cycle); retrying after back-off.")]
    private static partial void LogLoopFailure(ILogger logger, string failureType, long consecutiveFailures);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} returned a result for an unknown, duplicate or missing event.")]
    private static partial void LogUnexpectedResult(ILogger logger, string outputId);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Warning,
        Message = "Output adapter {OutputId} exhausted {Attempts} delivery attempts; event dead-lettered.")]
    private static partial void LogAttemptsExhausted(ILogger logger, string outputId, int attempts);

    // Information while busy is ordinary contention; Warning once it has lasted
    // BusyWarningAfter, so a write lock that is never released surfaces.
    [LoggerMessage(
        EventId = 1009,
        Message = "Queue database busy ({ConsecutiveAttempts} busy attempts since the last successful cycle, {BusySeconds} s in this busy interval); delivery retries after a short back-off.")]
    private static partial void LogQueueBusy(ILogger logger, LogLevel level, long consecutiveAttempts, long busySeconds);

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Information,
        Message = "Output adapter {OutputId} settled an event whose lease had already expired.")]
    private static partial void LogStaleLease(ILogger logger, string outputId);
}
