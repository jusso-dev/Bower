using Bower.Core;
using Bower.Packs;
using Bower.Pipeline;
using Bower.Source.Syslog;

namespace Bower.Collector;

/// <summary>
/// Collector side of the syslog source (see <see cref="PackRecordIntake"/>). Returning
/// <see cref="SyslogSubmitOutcome.Queued"/> means the event is durably enqueued; that is the
/// durable intake point. Syslog itself has no application-level acknowledgement.
/// </summary>
internal sealed class CollectorSyslogSink(
    PolicyBundle bundle,
    SecurityEventProcessor processor,
CollectorIdentity identity,
TimeProvider timeProvider) : ISyslogSink
{
    private readonly PackRecordIntake intake = new(bundle, processor, identity, timeProvider);

    public async ValueTask<SyslogSubmitOutcome> SubmitAsync(
        SyslogListenerOptions listener,
        SyslogRoute route,
        string record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(route);
        PackRecordOutcome outcome = await intake.SubmitAsync(
            route.Pack,
            route.Parser,
            $"syslog:{listener.Id}:{route.Pack}:{route.Parser}",
            record,
            cancellationToken);
        return outcome switch
        {
            PackRecordOutcome.Queued => SyslogSubmitOutcome.Queued,
            PackRecordOutcome.Duplicate => SyslogSubmitOutcome.Duplicate,
            PackRecordOutcome.Suppressed => SyslogSubmitOutcome.Suppressed,
            PackRecordOutcome.NotSelected => SyslogSubmitOutcome.NotSelected,
            PackRecordOutcome.Invalid => SyslogSubmitOutcome.Invalid,
            PackRecordOutcome.TooLarge => SyslogSubmitOutcome.TooLarge,
            PackRecordOutcome.Unavailable => SyslogSubmitOutcome.Unavailable,
            _ => SyslogSubmitOutcome.Rejected
        };
    }
}

internal static class SyslogRoutes
{
    public static CustomLogParserConfiguration? Parser(PolicyBundle bundle, SyslogRoute route) =>
        PackRecordIntake.Parser(bundle, route.Pack, route.Parser);

    /// <summary>Every route must name an active parser of a loaded signed pack; checked at start-up.</summary>
    public static void Validate(SyslogSourceConfiguration configuration, PolicyBundle bundle)
    {
        foreach (SyslogListenerOptions listener in configuration.Listeners)
        {
            foreach (SyslogRoute route in listener.Routes)
            {
                if (Parser(bundle, route) is null)
                {
                    throw new InvalidOperationException(
                        $"Syslog listener {listener.Id}: route pack {route.Pack} parser {route.Parser} is not an active parser of a loaded pack.");
                }
            }
        }
    }
}

/// <summary>Binds the syslog listeners with the host (a bind failure stops start-up) and stops them first on shutdown.</summary>
internal sealed partial class SyslogIntakeService(SyslogSource source, ILogger<SyslogIntakeService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await source.StartAsync(cancellationToken);
        foreach (SyslogListenerStatus listener in source.Snapshot())
        {
            LogListening(logger, listener.Id, listener.Protocol, listener.Endpoint);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken) =>
        await source.DisposeAsync().AsTask().WaitAsync(cancellationToken);

    [LoggerMessage(EventId = 1100, Level = LogLevel.Information, Message = "Syslog listener {Listener} ({Protocol}) listening on {Endpoint}.")]
    private static partial void LogListening(ILogger logger, string listener, string protocol, string endpoint);
}
