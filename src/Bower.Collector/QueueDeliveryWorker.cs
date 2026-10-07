using Bower.Abstractions;
using Bower.Persistence;

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
/// rather than a Hangfire job: delivery is continuous and its durability lives in the
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
        foreach (string eventId in result.AcknowledgedEventIds)
        {
            if (!leased.ContainsKey(eventId) || !settled.Add(eventId))
            {
                LogUnexpectedResult(logger, output.Id);
                continue;
            }

            await SettleAsync(
                () => queue.MarkDeliveredAsync(eventId, acknowledgement, cancellationToken));
        }

        foreach (DeliveryFailure failure in result.Failures)
        {
            if (!leased.TryGetValue(failure.EventId, out QueuedEvent? item) || !settled.Add(failure.EventId))
            {
                LogUnexpectedResult(logger, output.Id);
                continue;
            }

            await SettleFailureAsync(item, failure, cancellationToken);
        }

        // An adapter that neither acknowledged nor failed an event broke its contract;
        // retry rather than leave the event leased until the lease expires.
        foreach (QueuedEvent item in events.Where(item => !settled.Contains(item.EventId)))
        {
            LogUnexpectedResult(logger, output.Id);
            await SettleFailureAsync(
                item,
                new DeliveryFailure(item.EventId, "output-result-missing", true, null),
                cancellationToken);
        }

        return events.Count;
    }

    private Task SettleFailureAsync(
        QueuedEvent item,
        DeliveryFailure failure,
        CancellationToken cancellationToken)
    {
        if (!failure.IsRetryable)
        {
            return SettleAsync(
                () => queue.MarkDeadLetteredAsync(item.EventId, failure.Code, cancellationToken));
        }

        if (item.DeliveryAttempts >= options.MaximumDeliveryAttempts)
        {
            LogAttemptsExhausted(logger, output.Id, item.DeliveryAttempts);
            return SettleAsync(
                () => queue.MarkDeadLetteredAsync(
                    item.EventId,
                    $"max-attempts-exceeded:{failure.Code}",
                    cancellationToken));
        }

        DateTimeOffset retryAt = failure.RetryAfter
            ?? clock.GetUtcNow().Add(CalculateRetryDelay(item.DeliveryAttempts));
        return SettleAsync(
            () => queue.MarkRetryingAsync(item.EventId, failure.Code, retryAt, cancellationToken));
    }

    private async Task SettleAsync(Func<Task> transition)
    {
        try
        {
            await transition();
        }
        catch (InvalidQueueTransitionException)
        {
            // The lease expired and the event was reclaimed; the newer lease owns it now.
            LogStaleLease(logger, output.Id);
        }
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
