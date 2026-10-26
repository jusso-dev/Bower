using Azure.Core;
using Azure.Core.Pipeline;
using Bower.Abstractions;

namespace Bower.Output.AzureLogsIngestion;

/// <summary>Capacity signal from one upload attempt.</summary>
public enum ConcurrencySignal
{
    /// <summary>2xx: the RTT feeds the EWMA and may grow the limit.</summary>
    Healthy,

    /// <summary>Other 4xx: not a capacity signal.</summary>
    Neutral,

    /// <summary>429.</summary>
    Throttled,

    /// <summary>5xx.</summary>
    ServerError,

    /// <summary>408, network timeout or transport failure.</summary>
    Timeout
}

/// <summary>
/// AIMD request concurrency for one DCR stream (one output). Starts at the configured
/// maximum, so the healthy case is never slower than the fixed setting. Halves the limit
/// on 429, 5xx, 408 and transport failures; cuts it by a quarter when an RTT exceeds
/// twice the EWMA by at least <see cref="LatencySpikeFloorMilliseconds"/>; adds one slot after <c>limit</c> consecutive healthy attempts. One
/// decrease per window: attempts started before the last decrease cannot decrease (or
/// grow) it again. Deterministic: no clock or randomness inside; callers pass RTT and
/// time. Thread-safe. Waiting for a slot is the back-pressure: nothing is buffered
/// beyond the leased batch, which stays durable in the queue.
/// </summary>
public sealed class AdaptiveConcurrencyController
{
    public const int MinimumLimit = 1;

    /// <summary>Same ceiling as <see cref="AzureLogsIngestionOptions.MaximumConcurrency"/>.</summary>
    public const int MaximumAllowedLimit = 32;

    /// <summary>Latency spikes are only judged once the EWMA has this many samples.</summary>
    public const int LatencySamplesBeforeSpikes = 4;

    /// <summary>Absolute RTT rise needed for a spike, so jitter on fast links is not congestion.</summary>
    public const double LatencySpikeFloorMilliseconds = 250;

    private const double EwmaWeight = 0.25;

    private readonly Lock gate = new();
    private TaskCompletionSource changed = NewSignal();
    private int limit;
    private int inFlight;
    private int healthy;
    private long generation;
    private double ewmaMilliseconds;
    private long samples;
    private long requests;
    private long throttles;
    private long serverErrors;
    private long timeouts;
    private long latencySpikes;
    private long decreases;
    private long increases;
    private long pauses;
    private DateTimeOffset? pausedUntil;

    public AdaptiveConcurrencyController(int maximumLimit)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumLimit, MinimumLimit);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumLimit, MaximumAllowedLimit);
        MaximumLimit = maximumLimit;
        limit = maximumLimit;
    }

    public int MaximumLimit { get; }

    public int Limit
    {
        get
        {
            lock (gate) return limit;
        }
    }

    /// <summary>Waits until fewer than <see cref="Limit"/> requests are in flight.</summary>
    public async ValueTask AcquireAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (inFlight < limit)
                {
                    inFlight++;
                    return;
                }

                wait = changed.Task;
            }

            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public void Release()
    {
        lock (gate)
        {
            inFlight--;
            Signal();
        }
    }

    /// <summary>Window token for one attempt; pass it back to <see cref="Complete"/>.</summary>
    public long BeginAttempt()
    {
        lock (gate) return generation;
    }

    public void Complete(long attemptGeneration, ConcurrencySignal signal, TimeSpan roundTrip)
    {
        lock (gate)
        {
            requests++;
            switch (signal)
            {
                case ConcurrencySignal.Throttled:
                    throttles++;
                    Decrease(attemptGeneration, limit / 2);
                    break;
                case ConcurrencySignal.ServerError:
                    serverErrors++;
                    Decrease(attemptGeneration, limit / 2);
                    break;
                case ConcurrencySignal.Timeout:
                    timeouts++;
                    Decrease(attemptGeneration, limit / 2);
                    break;
                case ConcurrencySignal.Healthy:
                    double milliseconds = Math.Max(0, roundTrip.TotalMilliseconds);
                    bool spike = samples >= LatencySamplesBeforeSpikes && milliseconds > ewmaMilliseconds * 2
                        && milliseconds - ewmaMilliseconds >= LatencySpikeFloorMilliseconds;
                    ewmaMilliseconds = samples == 0
                        ? milliseconds
                        : ewmaMilliseconds + ((milliseconds - ewmaMilliseconds) * EwmaWeight);
                    samples++;
                    if (spike)
                    {
                        latencySpikes++;
                        Decrease(attemptGeneration, limit * 3 / 4);
                    }
                    else if (attemptGeneration == generation && ++healthy >= limit)
                    {
                        healthy = 0;
                        if (limit < MaximumLimit)
                        {
                            limit++;
                            increases++;
                            Signal();
                        }
                    }

                    break;
            }
        }
    }

    /// <summary>Records a server-requested pause (Retry-After). Extending one is not a new pause.</summary>
    public void Pause(DateTimeOffset until, DateTimeOffset now)
    {
        lock (gate)
        {
            if (until <= now) return;
            if (!(pausedUntil > now)) pauses++;
            if (!(pausedUntil >= until)) pausedUntil = until;
        }
    }

    public DateTimeOffset? PausedUntil(DateTimeOffset now)
    {
        lock (gate) return pausedUntil > now ? pausedUntil : null;
    }

    public OutputConcurrencySnapshot Snapshot(string outputId, DateTimeOffset now)
    {
        lock (gate)
        {
            return new OutputConcurrencySnapshot(
                outputId,
                limit,
                MinimumLimit,
                MaximumLimit,
                inFlight,
                samples == 0 ? null : (long)Math.Round(ewmaMilliseconds, MidpointRounding.AwayFromZero),
                requests,
                throttles,
                serverErrors,
                timeouts,
                latencySpikes,
                decreases,
                increases,
                pauses,
                pausedUntil > now ? pausedUntil : null);
        }
    }

    public static ConcurrencySignal Classify(int status) => status switch
    {
        >= 200 and < 300 => ConcurrencySignal.Healthy,
        429 => ConcurrencySignal.Throttled,
        0 or 408 => ConcurrencySignal.Timeout,
        >= 500 and < 600 => ConcurrencySignal.ServerError,
        _ => ConcurrencySignal.Neutral
    };

    private void Decrease(long attemptGeneration, int target)
    {
        // Attempts from an earlier window already caused (or missed) their decrease.
        if (attemptGeneration != generation) return;
        generation++;
        healthy = 0;
        target = Math.Max(MinimumLimit, target);
        if (target < limit)
        {
            limit = target;
            decreases++;
        }
    }

    private void Signal()
    {
        changed.TrySetResult();
        changed = NewSignal();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>
/// Per-retry pipeline policy: feeds every upload attempt (including SDK retries) to the
/// controller with its status and RTT. Caller cancellation is not a capacity signal.
/// </summary>
internal sealed class ConcurrencyObserverPolicy(AdaptiveConcurrencyController controller, TimeProvider clock)
    : HttpPipelinePolicy
{
    public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline) =>
        ProcessAsync(message, pipeline, false).AsTask().GetAwaiter().GetResult();

    public override ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline) =>
        ProcessAsync(message, pipeline, true);

    private async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline, bool async)
    {
        long attempt = controller.BeginAttempt();
        long started = clock.GetTimestamp();
        try
        {
            if (async)
            {
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }
            else
            {
                ProcessNext(message, pipeline);
            }
        }
        catch (Exception) when (!message.CancellationToken.IsCancellationRequested)
        {
            controller.Complete(attempt, ConcurrencySignal.Timeout, clock.GetElapsedTime(started));
            throw;
        }

        controller.Complete(
            attempt,
            AdaptiveConcurrencyController.Classify(message.Response.Status),
            clock.GetElapsedTime(started));
    }
}
