using Bower.Core;

namespace Bower.Collector;

/// <summary>
/// Closes ended suppression windows and queues their summaries. A hosted loop beside the
/// delivery worker rather than a scheduled job: it writes queue state, and suppressed counts
/// must reach the SIEM promptly even after the noisy source goes quiet.
/// </summary>
public sealed partial class SuppressionWindowWorker(
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    TimeProvider clock,
    ILogger<SuppressionWindowWorker> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int summaries = await processor.CloseSuppressionWindowsAsync(identity, stoppingToken);
                if (summaries > 0)
                {
                    LogSummariesQueued(logger, summaries);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Windows stay durable and are retried; a full queue or a rejected summary
                // must never stop collection.
                LogCloseFailure(logger, exception.GetType().Name);
            }

            try
            {
                await Task.Delay(Interval, clock, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    [LoggerMessage(
        EventId = 1301,
        Level = LogLevel.Information,
        Message = "Queued {Count} suppression summary event(s).")]
    private static partial void LogSummariesQueued(ILogger logger, int count);

    [LoggerMessage(
        EventId = 1302,
        Level = LogLevel.Warning,
        Message = "Closing suppression windows failed with {ExceptionType}; windows remain and will be retried.")]
    private static partial void LogCloseFailure(ILogger logger, string exceptionType);
}
