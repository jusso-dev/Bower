using System.Globalization;
using Bower.Forwarding;

namespace Bower.Agent.Cloud;

public sealed record CloudPassResult(
    int Messages,
    int Forwarded,
    int Rejected,
    int Unsupported,
    int Malformed,
    bool Backpressure);

/// <summary>
/// Receives messages from one cloud queue, translates them to candidate events and posts
/// them to the collector. At-least-once: a message is acknowledged only after every event
/// in it was accepted or definitively rejected; otherwise it is released for redelivery
/// and the collector deduplicates by deterministic event id.
/// </summary>
public sealed partial class CloudForwarderWorker(
    ICloudMessageSource source,
    ICloudMessageTranslator translator,
    CollectorClient collector,
    CloudAgentSettings settings,
    TimeProvider clock,
    ILogger<CloudForwarderWorker> logger) : BackgroundService
{
    private const int ExtendEvery = 200;
    private const int MaximumThrottleRetries = 30;
    private static readonly TimeSpan MaximumBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MinimumBackoff = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan backoff = MinimumBackoff;
        while (!stoppingToken.IsCancellationRequested)
        {
            bool wait;
            try
            {
                CloudPassResult result = await ProcessOnceAsync(stoppingToken);
                WriteHeartbeat();
                if (result.Messages > 0)
                {
                    LogPass(logger, source.Name, result.Messages, result.Forwarded, result.Rejected,
                        result.Unsupported, result.Malformed);
                }

                wait = result.Backpressure;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Receive failures (credentials, network, throttling) never crash the host.
                LogPassFailure(logger, source.Name, exception.GetType().Name);
                wait = true;
            }

            if (wait)
            {
                await Task.Delay(backoff, clock, stoppingToken);
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaximumBackoff.Ticks));
            }
            else
            {
                // Receives long-poll, so an idle queue does not spin.
                backoff = MinimumBackoff;
            }
        }
    }

    public async Task<CloudPassResult> ProcessOnceAsync(CancellationToken cancellationToken)
    {
        // Receiving while the collector is down would spend delivery attempts and push
        // healthy messages into the dead-letter queue.
        if (!await collector.IsReachableAsync(cancellationToken))
        {
            LogCollectorUnavailable(logger, source.Name);
            return new CloudPassResult(0, 0, 0, 0, 0, true);
        }

        IReadOnlyList<CloudMessage> messages = await source.ReceiveAsync(settings.BatchSize, cancellationToken);
        int forwarded = 0, rejected = 0, unsupported = 0, malformed = 0;
        for (int index = 0; index < messages.Count; index++)
        {
            CloudMessage message = messages[index];
            CloudTranslation translation;
            try
            {
                translation = await translator.TranslateAsync(message, cancellationToken);
            }
            catch (MalformedCloudMessageException exception)
            {
                malformed++;
                LogMalformed(logger, source.Name, message.Id, message.DeliveryAttempt, exception.Message);
                await TryAsync(() => source.ReleaseAsync(message, TimeSpan.Zero, cancellationToken));
                continue;
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // Transient (for example an S3 read failure): keep this and the remaining messages.
                LogTranslateFailure(logger, source.Name, message.Id, exception.GetType().Name);
                await ReleaseFromAsync(messages, index, cancellationToken);
                return new CloudPassResult(messages.Count, forwarded, rejected, unsupported, malformed, true);
            }

            if (translation.UnsupportedReason is not null)
            {
                // Default deny: not a security event Bower understands.
                unsupported++;
                LogUnsupported(logger, source.Name, message.Id, translation.UnsupportedReason);
                await TryAsync(() => source.AcknowledgeAsync(message, cancellationToken));
                continue;
            }

            (int accepted, int refused, SendOutcome? stoppedBy) = await ForwardAsync(message, translation.Events, cancellationToken);
            forwarded += accepted;
            rejected += refused;
            if (stoppedBy is not null)
            {
                if (stoppedBy is SendOutcome.Unauthorized)
                {
                    LogUnauthorized(logger, source.Name);
                }

                await ReleaseFromAsync(messages, index, cancellationToken);
                return new CloudPassResult(messages.Count, forwarded, rejected, unsupported, malformed, true);
            }

            await TryAsync(() => source.AcknowledgeAsync(message, cancellationToken));
        }

        return new CloudPassResult(messages.Count, forwarded, rejected, unsupported, malformed, false);
    }

    private async Task<(int Accepted, int Rejected, SendOutcome? StoppedBy)> ForwardAsync(
        CloudMessage message,
        IReadOnlyList<string> events,
        CancellationToken cancellationToken)
    {
        int accepted = 0, rejected = 0;
        for (int index = 0; index < events.Count; index++)
        {
            if (index > 0 && index % ExtendEvery == 0)
            {
                await TryAsync(() => source.ExtendAsync(message, settings.Lease, cancellationToken));
            }

            SendOutcome outcome = await collector.SendAsync(events[index], cancellationToken);
            for (int retry = 0; outcome is SendOutcome.Throttled && retry < MaximumThrottleRetries; retry++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), clock, cancellationToken);
                outcome = await collector.SendAsync(events[index], cancellationToken);
            }

            switch (outcome)
            {
                case SendOutcome.Accepted:
                    accepted++;
                    break;
                case SendOutcome.Rejected:
                    rejected++;
                    break;
                default:
                    return (accepted, rejected, outcome);
            }
        }

        return (accepted, rejected, null);
    }

    private async Task ReleaseFromAsync(IReadOnlyList<CloudMessage> messages, int start, CancellationToken cancellationToken)
    {
        for (int index = start; index < messages.Count; index++)
        {
            CloudMessage message = messages[index];
            await TryAsync(() => source.ReleaseAsync(message, settings.RetryDelay, cancellationToken));
        }
    }

    private async Task TryAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // A lost acknowledgement means redelivery, which the collector deduplicates.
            LogQueueCallFailure(logger, source.Name, exception.GetType().Name);
        }
    }

    private void WriteHeartbeat()
    {
        string path = settings.HeartbeatPath(source.Name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture));
    }

    [LoggerMessage(EventId = 4001, Level = LogLevel.Information,
        Message = "{Source} pass: {Messages} message(s), {Forwarded} event(s) forwarded, {Rejected} rejected by policy, {Unsupported} unsupported, {Malformed} malformed.")]
    private static partial void LogPass(ILogger logger, string source, int messages, int forwarded, int rejected, int unsupported, int malformed);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Warning, Message = "{Source} pass failed with {FailureType}; backing off.")]
    private static partial void LogPassFailure(ILogger logger, string source, string failureType);

    [LoggerMessage(EventId = 4003, Level = LogLevel.Warning,
        Message = "{Source} message {MessageId} (attempt {Attempt}) is malformed ({Reason}); released for the queue's dead-letter policy.")]
    private static partial void LogMalformed(ILogger logger, string source, string messageId, int attempt, string reason);

    [LoggerMessage(EventId = 4004, Level = LogLevel.Debug, Message = "{Source} message {MessageId} dropped: {Reason}.")]
    private static partial void LogUnsupported(ILogger logger, string source, string messageId, string reason);

    [LoggerMessage(EventId = 4005, Level = LogLevel.Warning,
        Message = "{Source} could not translate message {MessageId} ({FailureType}); it will be retried.")]
    private static partial void LogTranslateFailure(ILogger logger, string source, string messageId, string failureType);

    [LoggerMessage(EventId = 4006, Level = LogLevel.Error,
        Message = "Collector refused the ingest token for {Source}. Check BOWER_INGEST_TOKEN; forwarding is paused.")]
    private static partial void LogUnauthorized(ILogger logger, string source);

    [LoggerMessage(EventId = 4007, Level = LogLevel.Warning, Message = "{Source} queue call failed with {FailureType}.")]
    private static partial void LogQueueCallFailure(ILogger logger, string source, string failureType);

    [LoggerMessage(EventId = 4008, Level = LogLevel.Warning,
        Message = "Collector is unreachable; {Source} is not receiving until it recovers.")]
    private static partial void LogCollectorUnavailable(ILogger logger, string source);
}
