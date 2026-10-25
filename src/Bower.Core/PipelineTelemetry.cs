using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.Core;

/// <summary>
/// In-process selection counters and source activity. Counters show how many candidates and
/// bytes arrived, which stage and policy decided each, and what was queued, duplicated or
/// suppressed. They reset on restart and never hold payload content. Source activity is
/// loaded from and flushed to the queue so silence detection survives restarts.
/// </summary>
public sealed class PipelineTelemetry(TimeProvider clock)
{
    public const string NoPolicy = "-";
    public const int MaximumSources = 10_000;

    private readonly DateTimeOffset startedAt = clock.GetUtcNow();
    private readonly Lock gate = new();
    private readonly Dictionary<(ProcessingStage, string, DecisionAction), Counter> counters = [];
    private readonly Dictionary<(string, string), SourceActivity> sources = [];
    private readonly HashSet<(string, string)> dirty = [];

    public DateTimeOffset StartedAt => startedAt;

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
