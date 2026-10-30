using System.Text.Json;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;

namespace Bower.Collector;

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

/// <summary>Verified source records use the same redaction, policy, and queue as HTTP ingest.</summary>
internal sealed class PackRecordIntake(
    PolicyBundle bundle,
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    TimeProvider timeProvider)
{
    public static CustomLogParserConfiguration? Parser(PolicyBundle bundle, string pack, int parser)
    {
        LoadedPack? loaded = bundle.LoadedPacks.SingleOrDefault(item => item.Manifest.Id == pack);
        return loaded is not null && parser >= 0 && parser < loaded.Parsers.Count
            && loaded.Parsers[parser].Runtime is not null
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
        CustomLogParserConfiguration? parser = Parser(bundle, pack, parserIndex);
        if (parser is null)
        {
            return PackRecordOutcome.Invalid;
        }

        SecurityEventEnvelope? envelope;
        try
        {
            envelope = PackRuntime.Parse(parser, record, timeProvider.GetUtcNow());
        }
        catch (InvalidDataException exception) when (exception.Message == "pack-record-too-large")
        {
            return PackRecordOutcome.TooLarge;
        }
        catch (TransformException)
        {
            return PackRecordOutcome.Rejected;
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
        {
            return PackRecordOutcome.Invalid;
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

        if (result.Duplicate)
        {
            return PackRecordOutcome.Duplicate;
        }
        if (result.Queued)
        {
            return PackRecordOutcome.Queued;
        }
        return PackRecordOutcome.Rejected;
    }
}
