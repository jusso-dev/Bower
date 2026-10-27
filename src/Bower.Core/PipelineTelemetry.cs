using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.Core;

/// <summary>
/// In-process selection counters and source activity. Counters show how many candidates and
/// bytes arrived, which stage and policy decided each, and what was queued, duplicated or
/// suppressed. They reset on restart and never hold payload content. Source activity is
/// loaded from and flushed to the queue so silence detection survives restarts.
/// Intake counters (<see cref="IntakeSnapshot"/>) count every candidate submitted to
/// processing and every queue-capacity refusal. A <see cref="QueueCapacityReason"/> refusal
/// committed nothing and never reaches the selection counters; a
/// <see cref="PrivacyAlertCapacityReason"/> refusal follows a selection outcome that is
/// already recorded. They also reset only on restart; there is no reset operation.
/// </summary>
public sealed class PipelineTelemetry(TimeProvider clock)
{
    public const string NoPolicy = "-";
    public const int MaximumSources = 10_000;

    /// <summary>Bounded reason code: the queue refused the event itself; nothing was committed.</summary>
    public const string QueueCapacityReason = "queue-capacity";

    /// <summary>
    /// Bounded reason code: the queue refused the privacy alert after the event was decided
    /// (and, when accepted, committed).
    /// </summary>
    public const string PrivacyAlertCapacityReason = "privacy-alert-capacity";

    /// <summary>Most detector types counted by name; later new types count as <see cref="OtherRedactionType"/>.</summary>
    public const int MaximumRedactionTypes = 64;

    /// <summary>The bucket for detector types beyond <see cref="MaximumRedactionTypes"/>.</summary>
    public const string OtherRedactionType = "other";

    private readonly DateTimeOffset startedAt = clock.GetUtcNow();
    private readonly Lock gate = new();
    private readonly Dictionary<(ProcessingStage, string, DecisionAction), Counter> counters = [];
    private readonly Dictionary<(string, string), SourceActivity> sources = [];
    private readonly HashSet<(string, string)> dirty = [];
    private readonly Dictionary<string, long> redactions = new(StringComparer.Ordinal);
    private long attemptedRequests;
    private long attemptedBytes;
    private long capacityRefusals;
    private long capacityRefusedBytes;
    private long privacyAlertRefusals;
    private long privacyAlertRefusedBytes;

    // UtcTicks * 2 + reason bit (0 queue, 1 privacy alert); 0 before any refusal.
    private long lastRefusal;

    public DateTimeOffset StartedAt => startedAt;

    /// <summary>Counts one candidate submitted to processing, before any outcome is known.</summary>
    public void RecordAttempt(long bytesIn)
    {
        Interlocked.Increment(ref attemptedRequests);
        Interlocked.Add(ref attemptedBytes, bytesIn);
    }

    /// <summary>Counts one attempt whose event the queue refused for capacity (HTTP 503).</summary>
    public void RecordCapacityRefusal(long bytesIn)
    {
        MarkRefusal(0);
        Interlocked.Add(ref capacityRefusedBytes, bytesIn);
        Interlocked.Increment(ref capacityRefusals);
    }

    /// <summary>Counts one attempt whose privacy alert the queue refused for capacity (HTTP 503).</summary>
    public void RecordPrivacyAlertRefusal(long bytesIn)
    {
        MarkRefusal(1);
        Interlocked.Add(ref privacyAlertRefusedBytes, bytesIn);
        Interlocked.Increment(ref privacyAlertRefusals);
    }

    public IntakeMetricsSnapshot IntakeSnapshot()
    {
        // Read in the reverse of write order. Writers set the last refusal, then bytes, then
        // the count, and count the attempt before any of these, so a snapshot never shows a
        // refusal without its time and reason, or more refusals than attempts.
        long refusals = Interlocked.Read(ref capacityRefusals);
        long alertRefusals = Interlocked.Read(ref privacyAlertRefusals);
        long refusedBytes = Interlocked.Read(ref capacityRefusedBytes);
        long alertRefusedBytes = Interlocked.Read(ref privacyAlertRefusedBytes);
        long last = Interlocked.Read(ref lastRefusal);
        return new IntakeMetricsSnapshot(
            startedAt,
            Interlocked.Read(ref attemptedRequests),
            Interlocked.Read(ref attemptedBytes),
            refusals,
            refusedBytes,
            alertRefusals,
            alertRefusedBytes,
            last == 0 ? null : new DateTimeOffset(last >> 1, TimeSpan.Zero),
            last == 0 ? null : (last & 1) == 0 ? QueueCapacityReason : PrivacyAlertCapacityReason);
    }

    // Forward only, so concurrent refusals keep the latest time and its reason.
    private void MarkRefusal(long reasonBit)
    {
        long value = (clock.GetUtcNow().UtcTicks << 1) | reasonBit;
        long seen = Interlocked.Read(ref lastRefusal);
        while (value > seen)
        {
            long previous = Interlocked.CompareExchange(ref lastRefusal, value, seen);
            if (previous == seen)
            {
                break;
            }

            seen = previous;
        }
    }

    public void Record(ProcessingResult result, long bytesIn)
    {
        ArgumentNullException.ThrowIfNull(result);
        (ProcessingStage, string, DecisionAction) key =
            (result.Stage, result.PolicyDecision?.PolicyId ?? NoPolicy, result.Action);
        lock (gate)
        {
            if (!counters.TryGetValue(key, out Counter? counter))
            {
                counter = new Counter();
                counters.Add(key, counter);
            }

            counter.Events++;
            counter.BytesIn += bytesIn;
            counter.BytesQueued += result.QueuedBytes;
            counter.Queued += result.Queued ? 1 : 0;
            counter.Duplicates += result.Duplicate ? 1 : 0;
            counter.Suppressed += result.Suppressed ? 1 : 0;

            if (result.Source is { } source && (result.Queued || result.Duplicate || result.Suppressed))
            {
                (string, string) sourceKey = (source.Application, source.Environment);
                if (sources.TryGetValue(sourceKey, out SourceActivity? seen))
                {
                    sources[sourceKey] = seen with
                    {
                        LastSeenAt = clock.GetUtcNow(),
                        EventCount = seen.EventCount + 1
                    };
                    dirty.Add(sourceKey);
                }
                else if (sources.Count < MaximumSources)
                {
                    sources[sourceKey] = new SourceActivity(
                        source.Application,
                        source.Environment,
                        clock.GetUtcNow(),
                        1);
                    dirty.Add(sourceKey);
                }
            }
        }
    }

    /// <summary>
    /// Counts one queued event for each detector type (the id before any <c>:</c> sub-kind)
    /// whose values were removed or masked before the event was stored. Type ids only: never
    /// values, paths or event ids.
    /// </summary>
    public void RecordRedactions(IReadOnlyList<string>? detected)
    {
        if (detected is not { Count: > 0 })
        {
            return;
        }

        lock (gate)
        {
            HashSet<string> counted = new(StringComparer.Ordinal);
            foreach (string id in detected)
            {
                int colon = id.IndexOf(':', StringComparison.Ordinal);
                string type = colon > 0 ? id[..colon] : id;
                // One slot stays free for the overflow bucket.
                if (!redactions.ContainsKey(type) && redactions.Count >= MaximumRedactionTypes - 1)
                {
                    type = OtherRedactionType;
                }

                if (counted.Add(type))
                {
                    redactions[type] = redactions.GetValueOrDefault(type) + 1;
                }
            }
        }
    }

    /// <summary>Queued events per redacted detector type since <see cref="StartedAt"/>, ordinal by type.</summary>
    public RedactionSnapshot RedactionSnapshot()
    {
        lock (gate)
        {
            return new RedactionSnapshot(
                startedAt,
                redactions
                    .OrderBy(item => item.Key, StringComparer.Ordinal)
                    .Select(item => new RedactionCount(item.Key, item.Value))
                    .ToArray());
        }
    }

    /// <summary>Seeds activity from durable storage at start-up.</summary>
    public void Load(IEnumerable<SourceActivity> activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        lock (gate)
        {
            foreach (SourceActivity item in activity)
            {
                (string, string) key = (item.Application, item.Environment);
                if (!sources.TryGetValue(key, out SourceActivity? current) || current.LastSeenAt < item.LastSeenAt)
                {
                    if (sources.Count < MaximumSources || sources.ContainsKey(key))
                    {
                        sources[key] = item;
                    }
                }
            }
        }
    }

    /// <summary>Sources changed since the last call, for flushing to storage.</summary>
    public IReadOnlyList<SourceActivity> TakeChangedSources()
    {
        lock (gate)
        {
            SourceActivity[] changed = dirty.Select(key => sources[key]).ToArray();
            dirty.Clear();
            return changed;
        }
    }

    /// <summary>Returns sources to the changed set after a failed flush.</summary>
    public void MarkChanged(IEnumerable<SourceActivity> activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        lock (gate)
        {
            foreach (SourceActivity item in activity)
            {
                dirty.Add((item.Application, item.Environment));
            }
        }
    }

    public IReadOnlyList<SourceActivity> Sources()
    {
        lock (gate)
        {
            return sources.Values
                .OrderBy(item => item.Application, StringComparer.Ordinal)
                .ThenBy(item => item.Environment, StringComparer.Ordinal)
                .ToArray();
        }
    }

    public PipelineMetricsSnapshot Snapshot()
    {
        PipelineMetricsRow[] rows;
        lock (gate)
        {
            rows = counters
                .Select(item => new PipelineMetricsRow(
                    StageName(item.Key.Item1),
                    item.Key.Item2,
                    ActionName(item.Key.Item3),
                    item.Value.Events,
                    item.Value.Queued,
                    item.Value.Duplicates,
                    item.Value.Suppressed,
                    item.Value.BytesIn,
                    item.Value.BytesQueued))
                .OrderBy(row => row.Stage, StringComparer.Ordinal)
                .ThenBy(row => row.PolicyId, StringComparer.Ordinal)
                .ThenBy(row => row.Action, StringComparer.Ordinal)
                .ToArray();
        }

        long bytesIn = rows.Sum(row => row.BytesIn);
        long bytesQueued = rows.Sum(row => row.BytesQueued);
        return new PipelineMetricsSnapshot(
            startedAt,
            rows.Sum(row => row.Events),
            rows.Sum(row => row.Queued),
            rows.Sum(row => row.Duplicates),
            rows.Sum(row => row.Suppressed),
            bytesIn,
            bytesQueued,
            rows);
    }

    public static string StageName(ProcessingStage stage) => stage switch
    {
        ProcessingStage.Redaction => "redaction",
        ProcessingStage.Schema => "schema",
        ProcessingStage.Validation => "validation",
        ProcessingStage.Transform => "transform",
        _ => "policy"
    };

    public static string ActionName(DecisionAction action) => action switch
    {
        DecisionAction.RedactAndAccept => "redact-and-accept",
        DecisionAction.DeadLetter => "dead-letter",
        _ => action.ToString().ToLowerInvariant()
    };

    private sealed class Counter
    {
        public long Events { get; set; }

        public long Queued { get; set; }

        public long Duplicates { get; set; }

        public long Suppressed { get; set; }

        public long BytesIn { get; set; }

        public long BytesQueued { get; set; }
    }
}

/// <summary>
/// Selection counters since <see cref="StartedAt"/>. Queued bytes include Bower decision
/// context, so accepted traffic can exceed its input bytes.
/// </summary>
public sealed record PipelineMetricsSnapshot(
    DateTimeOffset StartedAt,
    long EventsIn,
    long EventsQueued,
    long Duplicates,
    long Suppressed,
    long BytesIn,
    long BytesQueued,
    IReadOnlyList<PipelineMetricsRow> Rows);

/// <summary>
/// Intake counters since <see cref="ObservedSince"/> (process start). Attempts are candidates
/// submitted to processing after authentication and authorisation. Capacity refusals are
/// attempts whose event the queue refused: nothing was committed. Privacy alert refusals are
/// attempts whose privacy alert the queue refused after the event's outcome was recorded in
/// the selection counters (an accepted event is then already queued). Metadata only: no
/// payloads, event ids or credentials.
/// </summary>
public sealed record IntakeMetricsSnapshot(
    DateTimeOffset ObservedSince,
    long AttemptedRequests,
    long AttemptedBytes,
    long CapacityRefusals,
    long CapacityRefusedBytes,
    long PrivacyAlertRefusals,
    long PrivacyAlertRefusedBytes,
    DateTimeOffset? LastRefusalAt,
    string? LastRefusalReason);

/// <summary>
/// Redaction counters since <see cref="ObservedSince"/> (process start): queued events per
/// detector type whose values were removed or masked. A restart starts a new count.
/// </summary>
public sealed record RedactionSnapshot(DateTimeOffset ObservedSince, IReadOnlyList<RedactionCount> Counts);

/// <summary>Queued events in which a detector type removed or masked at least one value.</summary>
public sealed record RedactionCount(string Type, long Events);

public sealed record PipelineMetricsRow(
    string Stage,
    string PolicyId,
    string Action,
    long Events,
    long Queued,
    long Duplicates,
    long Suppressed,
    long BytesIn,
    long BytesQueued);
