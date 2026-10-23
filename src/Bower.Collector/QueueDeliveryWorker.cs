using Bower.Abstractions;

namespace Bower.Collector;

public sealed record QueueDeliveryOptions
{
    public int BatchSize { get; init; } = 500;

    public TimeSpan LeaseDuration { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan IdleDelay { get; init; } = TimeSpan.FromSeconds(1);

    public TimeSpan ErrorDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Retryable failures dead-letter once an event has been leased this many times.</summary>
    public int MaximumDeliveryAttempts { get; init; } = 20;
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
    ILogger<QueueDeliveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int leased = await DeliverOnceAsync(stoppingToken);
                if (leased == 0)
                {
                    await Task.Delay(options.IdleDelay, clock, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Storage errors (for example SQLITE_BUSY) must not stop collection. Leased
                // events stay leased and are reclaimed when the lease expires.
                LogLoopFailure(logger, exception.GetType().Name);
                await Task.Delay(options.ErrorDelay, clock, stoppingToken);
            }
        }
    }

    /// <summary>Leases one batch, delivers it and settles every leased event exactly once.</summary>
    public async Task<int> DeliverOnceAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<QueuedEvent> events = await queue.LeaseAsync(
            options.BatchSize,
            options.LeaseDuration,
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
        try
        {
            result = await output.DeliverAsync(events, cancellationToken);
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
            // One queue transaction for every acknowledged event in the batch.
            IReadOnlyList<string> reclaimed = await queue.MarkDeliveredBatchAsync(
                delivered,
                acknowledgement,
                events.ToDictionary(item => item.EventId, item => item.LeaseToken!, StringComparer.Ordinal),
                cancellationToken);
            for (int index = 0; index < reclaimed.Count; index++)
            {
                // The lease expired and the event was reclaimed; the newer lease owns it now.
                LogStaleLease(logger, output.Id);
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

        if (failed.Count > 0)
        {
            // One queue transaction for every retrying and dead-lettered event in the batch.
            // On error nothing is settled and the events are redelivered after lease expiry.
            IReadOnlyList<string> reclaimed = await queue.MarkFailedBatchAsync(failed, cancellationToken);
            for (int index = 0; index < reclaimed.Count; index++)
            {
                // The lease expired and the event was reclaimed; the newer lease owns it now.
                LogStaleLease(logger, output.Id);
            }
        }

        return events.Count;
    }

    private FailureSettlement ToSettlement(QueuedEvent item, DeliveryFailure failure)
    {
        if (!failure.IsRetryable)
        {
            return new FailureSettlement(item.EventId, failure.Code, null, item.LeaseToken);
        }

        if (!failure.IsDestinationFailure && item.DeliveryAttempts >= options.MaximumDeliveryAttempts)
        {
            LogAttemptsExhausted(logger, output.Id, item.DeliveryAttempts);
            return new FailureSettlement(item.EventId, $"max-attempts-exceeded:{failure.Code}", null, item.LeaseToken);
        }

        DateTimeOffset retryAt = clock.GetUtcNow().Add(failure.IsDestinationFailure
            ? TimeSpan.FromSeconds(30)
            : CalculateRetryDelay(item.DeliveryAttempts));
        if (failure.RetryAfter > retryAt) retryAt = failure.RetryAfter.Value;
        return new FailureSettlement(item.EventId, failure.Code, retryAt, item.LeaseToken);
    }

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
        Message = "Delivery loop failed with {FailureType}; retrying after back-off.")]
    private static partial void LogLoopFailure(ILogger logger, string failureType);

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

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Information,
        Message = "Output adapter {OutputId} settled an event whose lease had already expired.")]
    private static partial void LogStaleLease(ILogger logger, string outputId);
}
