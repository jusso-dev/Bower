using Bower.Abstractions;

namespace Bower.Collector;

public sealed partial class QueueDeliveryWorker(
    IDurableEventStore queue,
    IOutputAdapter output,
    IClock clock,
    ILogger<QueueDeliveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            IReadOnlyList<QueuedEvent> events = await queue.LeaseAsync(
                maximumCount: 500,
                leaseDuration: TimeSpan.FromMinutes(5),
                stoppingToken);
            if (events.Count == 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                continue;
            }

            try
            {
                DeliveryResult result = await output.DeliverAsync(events, stoppingToken);
                string acknowledgement = result.DestinationAcknowledgement
                    ?? $"adapter:{output.Id}:acknowledged";
                foreach (string eventId in result.AcknowledgedEventIds)
                {
                    await queue.MarkDeliveredAsync(eventId, acknowledgement, stoppingToken);
                }

                foreach (DeliveryFailure failure in result.Failures)
                {
                    if (failure.IsRetryable)
                    {
                        QueuedEvent item = events.Single(value => value.EventId == failure.EventId);
                        DateTimeOffset retryAt = failure.RetryAfter
                            ?? clock.UtcNow.Add(CalculateRetryDelay(item.DeliveryAttempts));
                        await queue.MarkRetryingAsync(
                            failure.EventId,
                            failure.Code,
                            retryAt,
                            stoppingToken);
                    }
                    else
                    {
                        await queue.MarkDeadLetteredAsync(
                            failure.EventId,
                            failure.Code,
                            stoppingToken);
                    }
                }
            }
            catch (Exception exception) when (
                exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
            {
                LogOutputFailure(logger, output.Id, exception.GetType().Name);
                foreach (QueuedEvent item in events)
                {
                    await queue.MarkRetryingAsync(
                        item.EventId,
                        "output-adapter-failure",
                        clock.UtcNow.Add(CalculateRetryDelay(item.DeliveryAttempts)),
                        stoppingToken);
                }
            }
        }
    }

    private static TimeSpan CalculateRetryDelay(int attempt)
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
}
