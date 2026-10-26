using System.Globalization;
using Bower.Forwarding;

namespace Bower.Agent.Cloud;

/// <param name="LeaseLost">
/// Messages whose lease could not be renewed or passed its deadline. Work on them stopped and
/// they were neither acknowledged nor released: the queue redelivers them (retryable).
/// </param>
public sealed record CloudPassResult(
    int Messages,
    int Forwarded,
    int Rejected,
    int Unsupported,
    int Malformed,
    bool Backpressure,
    int LeaseLost = 0);

/// <summary>
/// Receives messages from one cloud queue, translates them to candidate events and posts
/// them to the collector. At-least-once: a message is acknowledged only after every event
/// in it was accepted or definitively rejected, and only while its lease is still held;
/// otherwise it is released or left for redelivery and the collector deduplicates by
/// deterministic event id.
/// </summary>
public sealed partial class CloudForwarderWorker(
    ICloudMessageSource source,
    ICloudMessageTranslator translator,
    CollectorClient collector,
    CloudAgentSettings settings,
    TimeProvider clock,
    ILogger<CloudForwarderWorker> logger) : BackgroundService
{
    private const int MaximumConcurrentRenewals = 4;
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
                        result.Unsupported, result.Malformed, result.LeaseLost);
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
        if (messages.Count == 0)
        {
            return new CloudPassResult(0, 0, 0, 0, 0, false);
        }

        // Every received message stays leased by elapsed time until it is settled, however long
        // translation, forwarding, throttling or earlier messages in the batch take. The renewal
        // tasks end with the batch.
        using CancellationTokenSource batch = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using SemaphoreSlim renewals = new(MaximumConcurrentRenewals);
        List<SourceLease> leases = [.. messages.Select(message => new SourceLease(message, clock, batch.Token))];
        Task[] keepers = [];
        try
        {
            // The queue's own visibility timeout or ack deadline is not known here (the Pub/Sub
            // subscription's is shorter than the lease), so take the lease before any work.
            await Task.WhenAll(leases.Select(lease => RenewAsync(lease, renewals, batch.Token)));
            keepers = [.. leases.Select(lease => KeepLeaseAsync(lease, renewals, batch.Token))];
            return await ProcessBatchAsync(leases, cancellationToken);
        }
        finally
        {
            // Synchronous: the renewal tasks stop before this pass returns.
            batch.Cancel();
            await Task.WhenAll(keepers);
            foreach (SourceLease lease in leases)
            {
                lease.Dispose();
            }
        }
    }

    private async Task<CloudPassResult> ProcessBatchAsync(List<SourceLease> leases, CancellationToken cancellationToken)
    {
        int forwarded = 0, rejected = 0, unsupported = 0, malformed = 0, leaseLost = 0;
        for (int index = 0; index < leases.Count; index++)
        {
            SourceLease lease = leases[index];
            CloudMessage message = lease.Message;
            if (lease.IsLost)
            {
                LeaseLost(lease);
                continue;
            }

            CloudTranslation translation;
            try
            {
                translation = await translator.TranslateAsync(message, lease.Token);
            }
            catch (MalformedCloudMessageException exception)
            {
                malformed++;
                LogMalformed(logger, source.Name, message.Id, message.DeliveryAttempt, exception.Message);
                await SettleAsync(lease, () => source.ReleaseAsync(message, TimeSpan.Zero, cancellationToken), cancellationToken);
                continue;
            }
            catch (OperationCanceledException) when (lease.IsLost && !cancellationToken.IsCancellationRequested)
            {
                LeaseLost(lease);
                continue;
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // Transient (for example an S3 read failure): keep this and the remaining messages.
                LogTranslateFailure(logger, source.Name, message.Id, exception.GetType().Name);
                await ReleaseFromAsync(leases, index, cancellationToken);
                return Result(true);
            }

            if (translation.UnsupportedReason is not null)
            {
                // Default deny: not a security event Bower understands.
                LogUnsupported(logger, source.Name, message.Id, translation.UnsupportedReason);
                if (await SettleAsync(lease, () => source.AcknowledgeAsync(message, cancellationToken), cancellationToken))
                {
                    unsupported++;
                }
                else
                {
                    LeaseLost(lease);
                }

                continue;
            }

            (int accepted, int refused, SendOutcome? stoppedBy, bool lost) =
                await ForwardAsync(lease, translation.Events, cancellationToken);
            forwarded += accepted;
            rejected += refused;
            if (lost)
            {
                LeaseLost(lease);
                continue;
            }

            if (stoppedBy is not null)
            {
                if (stoppedBy is SendOutcome.Unauthorized)
                {
                    LogUnauthorized(logger, source.Name);
                }

                await ReleaseFromAsync(leases, index, cancellationToken);
                return Result(true);
            }

            if (!await SettleAsync(lease, () => source.AcknowledgeAsync(message, cancellationToken), cancellationToken))
            {
                LeaseLost(lease);
            }
        }

        return Result(false);

        // Lost ownership is retryable: the message is neither acknowledged nor released (its
        // handle may already be stale) and the queue redelivers it after the lease.
        void LeaseLost(SourceLease lease)
        {
            leaseLost++;
            LogLeaseLost(logger, source.Name, lease.Message.Id, lease.Message.DeliveryAttempt, lease.LossReason ?? "lease lost");
        }

        CloudPassResult Result(bool backpressure) =>
            new(leases.Count, forwarded, rejected, unsupported, malformed, backpressure || leaseLost > 0, leaseLost);
    }

    private async Task<(int Accepted, int Rejected, SendOutcome? StoppedBy, bool LeaseLost)> ForwardAsync(
        SourceLease lease,
        IReadOnlyList<string> events,
        CancellationToken cancellationToken)
    {
        int accepted = 0, rejected = 0;
        try
        {
            for (int index = 0; index < events.Count; index++)
            {
                SendOutcome outcome = await collector.SendAsync(events[index], lease.Token);
                for (int retry = 0; outcome is SendOutcome.Throttled && retry < MaximumThrottleRetries; retry++)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), clock, lease.Token);
                    outcome = await collector.SendAsync(events[index], lease.Token);
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
                        return (accepted, rejected, outcome, false);
                }
            }
        }
        catch (OperationCanceledException) when (lease.IsLost && !cancellationToken.IsCancellationRequested)
        {
            return (accepted, rejected, null, true);
        }

        return (accepted, rejected, null, false);
    }

    private async Task KeepLeaseAsync(SourceLease lease, SemaphoreSlim renewals, CancellationToken cancellationToken)
    {
        // Renew at half the lease, so a slow or failed renewal still leaves time to stop.
        TimeSpan interval = settings.Lease / 2;
        try
        {
            while (lease.IsOutstanding)
            {
                await Task.Delay(interval, clock, cancellationToken);
                await RenewAsync(lease, renewals, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The batch finished or the host is stopping.
        }
    }

    private async Task RenewAsync(SourceLease lease, SemaphoreSlim renewals, CancellationToken cancellationToken)
    {
        await renewals.WaitAsync(cancellationToken);
        try
        {
            await lease.Gate.WaitAsync(cancellationToken);
            try
            {
                if (!lease.IsOutstanding)
                {
                    return;
                }

                DateTimeOffset sent = clock.GetUtcNow();
                try
                {
                    await source.ExtendAsync(lease.Message, settings.Lease, lease.Token);
                    lease.Renewed(sent, settings.Lease);
                }
                catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
                {
                    LogQueueCallFailure(logger, source.Name, exception.GetType().Name);
                    lease.Lose("lease renewal failed");
                }
            }
            finally
            {
                lease.Gate.Release();
            }
        }
        finally
        {
            renewals.Release();
        }
    }

    /// <summary>Acknowledges or releases a message only while this worker still owns it.</summary>
    private async Task<bool> SettleAsync(SourceLease lease, Func<Task> settle, CancellationToken cancellationToken)
    {
        // Serialised with renewal, so a late extension cannot override a release delay.
        await lease.Gate.WaitAsync(cancellationToken);
        try
        {
            if (!lease.TrySettle())
            {
                return false;
            }

            await TryAsync(settle);
            return true;
        }
        finally
        {
            lease.Gate.Release();
        }
    }

    private async Task ReleaseFromAsync(List<SourceLease> leases, int start, CancellationToken cancellationToken)
    {
        for (int index = start; index < leases.Count; index++)
        {
            CloudMessage message = leases[index].Message;
            await SettleAsync(leases[index], () => source.ReleaseAsync(message, settings.RetryDelay, cancellationToken), cancellationToken);
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
        Message = "{Source} pass: {Messages} message(s), {Forwarded} event(s) forwarded, {Rejected} rejected by policy, {Unsupported} unsupported, {Malformed} malformed, {LeaseLost} lease(s) lost.")]
    private static partial void LogPass(ILogger logger, string source, int messages, int forwarded, int rejected, int unsupported, int malformed, int leaseLost);

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

    [LoggerMessage(EventId = 4009, Level = LogLevel.Warning,
        Message = "{Source} message {MessageId} (attempt {Attempt}): {Reason}; work stopped and the queue will redeliver it.")]
    private static partial void LogLeaseLost(ILogger logger, string source, string messageId, int attempt, string reason);

    /// <summary>
    /// Ownership of one received message. Ownership is judged by the clock against the renewed
    /// deadline, so a late timer callback can never let the worker extend, acknowledge or
    /// release an expired lease; the expiry timer only stops in-flight work promptly. The token
    /// cancels the message's work when a renewal fails or the deadline passes; a lost lease is
    /// never acknowledged or released.
    /// </summary>
    private sealed class SourceLease : IDisposable
    {
        private const string DeadlinePassed = "lease deadline passed";
        private readonly Lock sync = new();
        private readonly TimeProvider clock;
        private readonly CancellationTokenSource ownership;
        private readonly ITimer expiry;
        // Null until the first renewal; until then the message is not worked on.
        private DateTimeOffset? deadline;
        private string? lossReason;
        private bool settled;

        public SourceLease(CloudMessage message, TimeProvider clock, CancellationToken batch)
        {
            Message = message;
            this.clock = clock;
            ownership = CancellationTokenSource.CreateLinkedTokenSource(batch);
            expiry = clock.CreateTimer(
                static state => ((SourceLease)state!).Lose(DeadlinePassed),
                this,
                Timeout.InfiniteTimeSpan,
                Timeout.InfiniteTimeSpan);
        }

        public CloudMessage Message { get; }

        /// <summary>Serialises renewal with acknowledgement and release.</summary>
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public CancellationToken Token => ownership.Token;

        public string? LossReason
        {
            get
            {
                lock (sync)
                {
                    return lossReason;
                }
            }
        }

        public bool IsLost
        {
            get
            {
                ExpireIfDue();
                return LossReason is not null;
            }
        }

        public bool IsOutstanding
        {
            get
            {
                ExpireIfDue();
                lock (sync)
                {
                    return !settled && lossReason is null;
                }
            }
        }

        /// <summary>Records a renewal whose request was sent at <paramref name="sent"/>.</summary>
        public void Renewed(DateTimeOffset sent, TimeSpan lease)
        {
            bool expired;
            lock (sync)
            {
                if (settled || lossReason is not null)
                {
                    return;
                }

                // The new deadline counts from when the request was sent, not when it returned.
                TimeSpan remaining = sent + lease - clock.GetUtcNow();
                expired = remaining <= TimeSpan.Zero;
                if (!expired)
                {
                    deadline = sent + lease;
                    expiry.Change(remaining, Timeout.InfiniteTimeSpan);
                }
            }

            if (expired)
            {
                Lose(DeadlinePassed);
            }
        }

        /// <summary>Claims the message for acknowledgement or release; false once ownership is lost.</summary>
        public bool TrySettle()
        {
            ExpireIfDue();
            lock (sync)
            {
                if (lossReason is not null || deadline is null || clock.GetUtcNow() >= deadline)
                {
                    return false;
                }

                settled = true;
                expiry.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                return true;
            }
        }

        public void Lose(string reason)
        {
            lock (sync)
            {
                if (settled || lossReason is not null)
                {
                    return;
                }

                lossReason = reason;
            }

            try
            {
                ownership.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The batch already finished; nothing is left to stop.
            }
        }

        public void Dispose()
        {
            expiry.Dispose();
            ownership.Dispose();
            Gate.Dispose();
        }

        private void ExpireIfDue()
        {
            bool due;
            lock (sync)
            {
                due = !settled && lossReason is null && deadline is not null && clock.GetUtcNow() >= deadline;
            }

            if (due)
            {
                Lose(DeadlinePassed);
            }
        }
    }
}
