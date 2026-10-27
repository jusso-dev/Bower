using System.Collections.Concurrent;
using System.Globalization;
using System.Security;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Source.WindowsEventLog;

namespace Bower.UnitTests;

/// <summary>Recorded event XML and synthetic events in the shape <c>EvtRender</c> produces.</summary>
internal static class WindowsEventFixtures
{
    public static string Read(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "windows-eventlog", name));

    public static string Event(
        long recordId,
        int eventId,
        string provider = "BowerTest",
        string channel = "Application",
        string computer = "host01",
        string? time = null,
        params (string Name, string Value)[] data)
    {
        string created = time ?? DateTimeOffset.UnixEpoch.AddDays(20_000).AddSeconds(recordId)
            .UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string items = string.Concat(data.Select(item =>
            $"<Data Name='{SecurityElement.Escape(item.Name)}'>{SecurityElement.Escape(item.Value)}</Data>"));
        return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            + $"<Provider Name='{SecurityElement.Escape(provider)}'/><EventID>{eventId}</EventID><Level>4</Level>"
            + $"<TimeCreated SystemTime='{created}'/><EventRecordID>{recordId}</EventRecordID>"
            + $"<Channel>{SecurityElement.Escape(channel)}</Channel><Computer>{SecurityElement.Escape(computer)}</Computer><Security/>"
            + $"</System><EventData>{items}</EventData></Event>";
    }
}

/// <summary>
/// In-memory channel that evaluates the subscription query like the event log service:
/// only matching events after the bookmark are ever returned.
/// </summary>
internal sealed class FakeWindowsEventChannel : IWindowsEventChannel
{
    private readonly Lock gate = new();
    private readonly List<(long RecordId, int EventId, string Provider, string Xml)> events = [];

    public List<WindowsEventQuery> Queries { get; } = [];

    /// <summary>Every record id this channel ever handed out (the only events read into the collector).</summary>
    public List<long> Returned { get; } = [];

    public string? FailWith { get; set; }

    /// <summary>Overrides the reported oldest record (simulates overwritten events).</summary>
    public long? OldestOverride { get; set; }

    public int Disposed { get; private set; }

    public void Write(long recordId, int eventId, string provider, string xml)
    {
        lock (gate)
        {
            events.Add((recordId, eventId, provider, xml));
        }
    }

    public void Add(string xml)
    {
        WindowsEvent parsed = WindowsEventXml.Parse(xml);
        Write(parsed.RecordId, parsed.EventId, parsed.Provider, xml);
    }

    public void Clear()
    {
        lock (gate)
        {
            events.Clear();
        }
    }

    public WindowsChannelRange GetRange()
    {
        lock (gate)
        {
            Fail();
            return events.Count == 0
                ? new WindowsChannelRange(0, 0)
                : new WindowsChannelRange(OldestOverride ?? events.Min(item => item.RecordId), events.Max(item => item.RecordId));
        }
    }

    public IReadOnlyList<WindowsRawEvent> Read(WindowsEventQuery query, int maximum, bool includeMessage, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Fail();
            Queries.Add(query);
            List<WindowsRawEvent> result = [.. events
                .Where(item => query.Matches(item.EventId, item.Provider, item.RecordId))
                .OrderBy(item => item.RecordId)
                .Take(maximum)
                .Select(item => new WindowsRawEvent(item.RecordId, item.Xml, includeMessage ? "rendered message-marker" : null))];
            Returned.AddRange(result.Select(item => item.RecordId));
            return result;
        }
    }

    public void Dispose() => Disposed++;

    private void Fail()
    {
        if (FailWith is { } code)
        {
            throw new WindowsEventChannelException(code);
        }
    }
}

internal sealed class FakeWindowsEventChannelFactory : IWindowsEventChannelFactory
{
    public ConcurrentDictionary<string, FakeWindowsEventChannel> Channels { get; } = new(StringComparer.OrdinalIgnoreCase);

    public FakeWindowsEventChannel this[string channel] => Channels.GetOrAdd(channel, _ => new FakeWindowsEventChannel());

    public IWindowsEventChannel Open(string channel) => this[channel];
}

/// <summary>Sink with the queue's idempotency: a repeated record id is a duplicate.</summary>
internal sealed class RecordingWindowsEventSink : IWindowsEventSink
{
    private readonly ConcurrentDictionary<string, string> queued = new(StringComparer.Ordinal);

    public ConcurrentQueue<string> Records { get; } = new();

    public Func<string, WindowsEventSubmitOutcome?>? Override { get; set; }

    public IReadOnlyCollection<string> Queued => [.. queued.Keys];

    public ValueTask<WindowsEventSubmitOutcome> SubmitAsync(
        WindowsEventSubscriptionOptions subscription,
        string record,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Records.Enqueue(record);
        if (Override?.Invoke(record) is { } outcome)
        {
            return ValueTask.FromResult(outcome);
        }

        using JsonDocument document = JsonDocument.Parse(record);
        string id = document.RootElement.GetProperty("id").GetString()!;
        return ValueTask.FromResult(queued.TryAdd(id, record) ? WindowsEventSubmitOutcome.Queued : WindowsEventSubmitOutcome.Duplicate);
    }
}

/// <summary>Cursor store that can simulate a crash right before the bookmark commit.</summary>
internal sealed class CrashingCursorStore(ISourceCursorStore inner) : ISourceCursorStore
{
    public int FailNextCommits { get; set; }

    public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default) =>
        inner.ReadAsync(sourceId, cancellationToken);

    public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        if (FailNextCommits > 0)
        {
            FailNextCommits--;
            throw new IOException("simulated crash before the bookmark commit");
        }

        return inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
    }
}
