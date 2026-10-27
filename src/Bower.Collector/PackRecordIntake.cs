using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;

namespace Bower.Collector;

/// <summary>What happened to one source record handed to a pack parser.</summary>
internal enum PackRecordOutcome
{
    Queued,
    Duplicate,
    Suppressed,
    NotSelected,
    Rejected,
    Invalid,
    TooLarge,
    Unavailable
}

/// <summary>
/// The collector side shared by in-process sources (syslog, Windows Event Log). A record
/// becomes an event only through a signed pack parser (its match filter must select it),
/// then redaction, policy and the durable queue, exactly like <c>/v1/packs/.../events</c>.
/// <see cref="PackRecordOutcome.Queued"/> means the event is durably enqueued.
/// </summary>
internal sealed class PackRecordIntake(
    PolicyBundle bundle,
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    ManagedPrivacyProfileState managedPrivacy,
    PipelineTelemetry telemetry,
    TimeProvider timeProvider,
    EventTap? tap = null)
{
    /// <summary>The active parser of a loaded signed pack, or null.</summary>
    public static CustomLogParserConfiguration? Parser(PolicyBundle bundle, string pack, int parser)
    {
        LoadedPack? loaded = bundle.LoadedPacks.SingleOrDefault(item => item.Manifest.Id == pack);
        return loaded is not null && parser < loaded.Parsers.Count && loaded.Parsers[parser].Runtime is not null
            ? loaded.Parsers[parser]
            : null;
    }

    public async ValueTask<PackRecordOutcome> SubmitAsync(
        string pack,
        int parserIndex,
        string sourceAdapter,
        string record,
        CancellationToken cancellationToken)
    {
        if (!managedPrivacy.AcceptsEvents)
        {
            return PackRecordOutcome.Unavailable;
        }

        CustomLogParserConfiguration parser = Parser(bundle, pack, parserIndex)!;
        SecurityEventEnvelope? envelope;
        try
        {
            envelope = PackRuntime.Parse(parser, record, timeProvider.GetUtcNow());
        }
        catch (InvalidDataException exception) when (exception.Message == "pack-record-too-large")
        {
            return PackRecordOutcome.TooLarge;
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
        {
            return PackRecordOutcome.Invalid;
        }
        catch (TransformException exception)
        {
            // Quarantine without persisting, as /v1/packs/.../events does: the record never
            // reaches redaction, policy or the queue, and only the stable code is counted.
            ProcessingResult quarantined =
                ProcessingResult.Failed(DecisionAction.Quarantine, exception.Code, ProcessingStage.Transform);
            telemetry.Record(quarantined, Encoding.UTF8.GetByteCount(record));
            tap?.Publish(quarantined);
            return PackRecordOutcome.Rejected;
        }

        if (envelope is null)
        {
            return PackRecordOutcome.NotSelected;
        }

        ProcessingResult result;
        try
        {
            result = await processor.ProcessAsync(
                JsonSerializer.Serialize(envelope, BowerJson.Envelope),
                identity with { SourceAdapter = sourceAdapter },
                cancellationToken);
        }
        catch (QueueCapacityExceededException)
        {
            return PackRecordOutcome.Unavailable;
        }

        if (result.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
        {
            return PackRecordOutcome.Rejected;
        }

        return result.Suppressed ? PackRecordOutcome.Suppressed
            : result.Duplicate ? PackRecordOutcome.Duplicate
            : PackRecordOutcome.Queued;
    }
}
