namespace Bower.Collector;

/// <summary>Process-local, payload-free conflict counts with bounded producer cardinality.</summary>
public sealed class EventIdentityConflicts
{
    public const string Reason = "event-identity-conflict";
    public const string Remediation = "Preserve the upstream event without acknowledging or discarding it. Repair the producer's globally unique, retry-stable event ID mapping before retrying; do not automatically regenerate IDs.";
    public const int MaximumProducers = 1024;
    private readonly Lock gate = new();
    private readonly Dictionary<string, long> producers = new(StringComparer.Ordinal);
    private long unattributed;
    private long overflow;

    /// <summary>Producer must come from ingest authentication, never the event body.</summary>
    public void Record(string producer, bool authenticated)
    {
        lock (gate)
        {
            if (!authenticated)
            {
                unattributed = Increment(unattributed);
            }
            else if (producers.TryGetValue(producer, out long count))
            {
                producers[producer] = Increment(count);
            }
            else if (producers.Count < MaximumProducers && producer.Length is > 0 and <= 64)
            {
                producers.Add(producer, 1);
            }
            else
            {
                overflow = Increment(overflow);
            }
        }
    }

    public EventIdentityConflictSnapshot Snapshot()
    {
        lock (gate)
        {
            return new(producers.OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => new ProducerConflictCount(item.Key, item.Value)).ToArray(), unattributed, overflow);
        }
    }

    private static long Increment(long count) => count == long.MaxValue ? count : count + 1;
}

public sealed record ProducerConflictCount(string Producer, long Count);

public sealed record EventIdentityConflictSnapshot(
    IReadOnlyList<ProducerConflictCount> Producers, long Unattributed, long Overflow);
