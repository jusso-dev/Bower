using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace Bower.Source.WindowsEventLog;

/// <summary>
/// The Windows event log service behind <see cref="IWindowsEventChannelFactory"/>
/// (<c>EvtQuery</c>, <c>EvtNext</c>, <c>EvtRender</c> through <c>System.Diagnostics.Eventing.Reader</c>).
/// Windows only; everything else in this library is platform-neutral.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogChannelFactory : IWindowsEventChannelFactory
{
    public IWindowsEventChannel Open(string channel)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(channel);
        return new WindowsEventLogChannel(channel);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsEventLogChannel(string channel) : IWindowsEventChannel
{
    // The local machine's event log service, with the collector's own identity.
    private readonly EventLogSession session = new();

    public WindowsChannelRange GetRange()
    {
        try
        {
            EventLogInformation information = session.GetLogInformation(channel, PathType.LogName);
            long count = information.RecordCount ?? 0;
            long oldest = information.OldestRecordNumber ?? 0;
            return count <= 0 || oldest <= 0 ? new WindowsChannelRange(0, 0) : new WindowsChannelRange(oldest, oldest + count - 1);
        }
        catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException)
        {
            throw Map(exception);
        }
    }

    public IReadOnlyList<WindowsRawEvent> Read(WindowsEventQuery query, int maximum, bool includeMessage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        // The filter is evaluated by the event log service: events outside the allow-list
        // or before the bookmark are never returned to this process.
        EventLogQuery request = new(channel, PathType.LogName, query.ToXPath())
        {
            Session = session,
            ReverseDirection = false,
            TolerateQueryErrors = false
        };
        List<WindowsRawEvent> events = [];
        try
        {
            using EventLogReader reader = new(request) { BatchSize = maximum };
            while (events.Count < maximum)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using EventRecord? record = reader.ReadEvent();
                if (record is null)
                {
                    break;
                }

                long recordId = record.RecordId ?? throw new WindowsEventChannelException(WindowsEventChannelFailures.ReadFailed);
                string? message = null;
                if (includeMessage)
                {
                    try
                    {
                        message = record.FormatDescription();
                    }
                    catch (EventLogException)
                    {
                        // No publisher metadata on this machine: the record has no message field.
                    }
                }

                events.Add(new WindowsRawEvent(recordId, record.ToXml(), message));
            }
        }
        catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException)
        {
            throw Map(exception);
        }

        return events;
    }

    public void Dispose() => session.Dispose();

    // Codes only: Windows messages can quote the query or the channel's configuration.
    private static WindowsEventChannelException Map(Exception exception) => exception switch
    {
        EventLogNotFoundException => new WindowsEventChannelException(WindowsEventChannelFailures.ChannelNotFound, exception),
        UnauthorizedAccessException => new WindowsEventChannelException(WindowsEventChannelFailures.AccessDenied, exception),
        EventLogInvalidDataException => new WindowsEventChannelException(WindowsEventChannelFailures.QueryInvalid, exception),
        _ => new WindowsEventChannelException(WindowsEventChannelFailures.ReadFailed, exception)
    };
}
