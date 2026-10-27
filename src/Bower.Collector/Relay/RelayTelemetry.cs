using System.Collections.Concurrent;

namespace Bower.Collector.Relay;

/// <summary>
/// Relay counters since start, for /v1/status. Metadata only: collector ids come from the
/// downstreams file, never from request bodies. Process-local; resets on restart.
/// </summary>
public sealed class RelayTelemetry
{
    private readonly ConcurrentDictionary<string, Downstream> downstreams = new(StringComparer.Ordinal);
    private long tunnelsOpen;
    private long tunnelsOpened;
    private long tunnelsRefused;

    public RelayTelemetry(IEnumerable<string> collectorIds)
    {
        foreach (string id in collectorIds)
        {
            downstreams[id] = new Downstream();
        }
    }

    public void RecordBatch(string collectorId, int accepted, int duplicates, int rejected, DateTimeOffset at)
    {
        if (!downstreams.TryGetValue(collectorId, out Downstream? item))
        {
            return;
        }

        Interlocked.Increment(ref item.Batches);
        Interlocked.Add(ref item.Accepted, accepted);
        Interlocked.Add(ref item.Duplicates, duplicates);
        Interlocked.Add(ref item.Rejected, rejected);
        Interlocked.Exchange(ref item.LastBatchTicks, at.UtcTicks);
    }

    public void RecordTunnelOpened()
    {
        Interlocked.Increment(ref tunnelsOpen);
        Interlocked.Increment(ref tunnelsOpened);
    }

    public void RecordTunnelClosed() => Interlocked.Decrement(ref tunnelsOpen);

    public void RecordTunnelRefused() => Interlocked.Increment(ref tunnelsRefused);

    public RelayStatusSnapshot Snapshot() => new(
        [.. downstreams.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item =>
        {
            long ticks = Interlocked.Read(ref item.Value.LastBatchTicks);
            return new RelayDownstreamSnapshot(
                item.Key,
                Interlocked.Read(ref item.Value.Batches),
                Interlocked.Read(ref item.Value.Accepted),
                Interlocked.Read(ref item.Value.Duplicates),
                Interlocked.Read(ref item.Value.Rejected),
                ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero));
        })],
        new RelayTunnelSnapshot(
            Interlocked.Read(ref tunnelsOpen),
            Interlocked.Read(ref tunnelsOpened),
            Interlocked.Read(ref tunnelsRefused)));

    private sealed class Downstream
    {
        public long Batches;
        public long Accepted;
        public long Duplicates;
        public long Rejected;
        public long LastBatchTicks;
    }
}

public sealed record RelayStatusSnapshot(
    IReadOnlyList<RelayDownstreamSnapshot> Downstreams,
    RelayTunnelSnapshot Tunnels);

public sealed record RelayDownstreamSnapshot(
    string CollectorId,
    long Batches,
    long Accepted,
    long Duplicates,
    long Rejected,
    DateTimeOffset? LastBatchAt);

public sealed record RelayTunnelSnapshot(long Open, long Opened, long Refused);
