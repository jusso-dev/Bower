using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;
using Bower.Source.Syslog;

namespace Bower.Collector;

/// <summary>
/// Collector side of the syslog source. A record becomes an event only through a signed
/// pack parser (its match filter must select it), then redaction, policy and the durable
/// queue, exactly like <c>/v1/packs/.../events</c>. Returning <see cref="SyslogSubmitOutcome.Queued"/>
/// means the event is durably enqueued; that is the TCP acknowledgement point.
/// </summary>
internal sealed class CollectorSyslogSink(
    PolicyBundle bundle,
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    ManagedPrivacyProfileState managedPrivacy,
    PipelineTelemetry telemetry,
    TimeProvider timeProvider) : ISyslogSink
{
    public async ValueTask<SyslogSubmitOutcome> SubmitAsync(
        SyslogListenerOptions listener,
        SyslogRoute route,
        string record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(route);
        if (!managedPrivacy.AcceptsEvents)
        {
            return SyslogSubmitOutcome.Unavailable;
        }

        CustomLogParserConfiguration parser = SyslogRoutes.Parser(bundle, route)!;
        SecurityEventEnvelope? envelope;
        try
        {
            envelope = PackRuntime.Parse(parser, record, timeProvider.GetUtcNow());
        }
        catch (InvalidDataException exception) when (exception.Message == "pack-record-too-large")
        {
            return SyslogSubmitOutcome.TooLarge;
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
        {
            return SyslogSubmitOutcome.Invalid;
        }
        catch (TransformException exception)
        {
            // Quarantine without persisting, as /v1/packs/.../events does: the record never
            // reaches redaction, policy or the queue, and only the stable code is counted.
            telemetry.Record(
                ProcessingResult.Failed(DecisionAction.Quarantine, exception.Code, ProcessingStage.Transform),
                Encoding.UTF8.GetByteCount(record));
            return SyslogSubmitOutcome.Rejected;
        }

        if (envelope is null)
        {
            return SyslogSubmitOutcome.NotSelected;
        }

        ProcessingResult result;
        try
        {
            result = await processor.ProcessAsync(
                JsonSerializer.Serialize(envelope, BowerJson.Envelope),
                identity with { SourceAdapter = $"syslog:{listener.Id}:{route.Pack}:{route.Parser}" },
                cancellationToken);
        }
        catch (QueueCapacityExceededException)
        {
            return SyslogSubmitOutcome.Unavailable;
        }

        if (result.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            return SyslogSubmitOutcome.Rejected;
        }

        return result.Suppressed ? SyslogSubmitOutcome.Suppressed
            : result.Duplicate ? SyslogSubmitOutcome.Duplicate
            : SyslogSubmitOutcome.Queued;
    }
}

internal static class SyslogRoutes
{
    public static CustomLogParserConfiguration? Parser(PolicyBundle bundle, SyslogRoute route)
    {
        LoadedPack? pack = bundle.LoadedPacks.SingleOrDefault(item => item.Manifest.Id == route.Pack);
        return pack is not null && route.Parser < pack.Parsers.Count && pack.Parsers[route.Parser].Runtime is not null
            ? pack.Parsers[route.Parser]
            : null;
    }

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

    public async Task StopAsync(CancellationToken cancellationToken) => await source.DisposeAsync();

    [LoggerMessage(EventId = 1100, Level = LogLevel.Information, Message = "Syslog listener {Listener} ({Protocol}) listening on {Endpoint}.")]
    private static partial void LogListening(ILogger logger, string listener, string protocol, string endpoint);
}
