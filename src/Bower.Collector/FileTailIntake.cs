using Bower.Packs;
using Bower.Persistence;
using Bower.Source.File;

namespace Bower.Collector;

/// <summary>
/// Collector side of the file tail source (see <see cref="PackRecordIntake"/>).
/// <see cref="FileTailSubmitOutcome.Queued"/> means durably enqueued; only then can the
/// cursor move past the line.
/// </summary>
internal sealed class CollectorFileTailSink(PackRecordIntake intake) : IFileTailSink
{
    public async ValueTask<FileTailSubmitOutcome> SubmitAsync(
        FileTailInputOptions input,
        string record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        PackRecordOutcome outcome = await intake.SubmitAsync(
            input.Route.Pack,
            input.Route.Parser,
            $"file:{input.Id}:{input.Route.Pack}:{input.Route.Parser}",
            record,
            cancellationToken);
        return outcome switch
        {
            PackRecordOutcome.Queued => FileTailSubmitOutcome.Queued,
            PackRecordOutcome.Duplicate => FileTailSubmitOutcome.Duplicate,
            PackRecordOutcome.Suppressed => FileTailSubmitOutcome.Suppressed,
            PackRecordOutcome.NotSelected => FileTailSubmitOutcome.NotSelected,
            PackRecordOutcome.Invalid => FileTailSubmitOutcome.Invalid,
            PackRecordOutcome.TooLarge => FileTailSubmitOutcome.TooLarge,
            PackRecordOutcome.Unavailable => FileTailSubmitOutcome.Unavailable,
            _ => FileTailSubmitOutcome.Rejected
        };
    }
}

internal static class FileTailRoutes
{
    /// <summary>Every input must route to an active parser of a loaded signed pack; checked at start-up and before a signed reload.</summary>
    public static void Validate(FileTailSourceConfiguration configuration, PolicyBundle bundle)
    {
        foreach (FileTailInputOptions input in configuration.Inputs)
        {
            if (PackRecordIntake.Parser(bundle, input.Route.Pack, input.Route.Parser) is null)
            {
                throw new InvalidOperationException(
                    $"File tail input {input.Id}: route pack {input.Route.Pack} parser {input.Route.Parser} is not an active parser of a loaded pack.");
            }
        }
    }
}

/// <summary>Cursor table in the queue database, then the input loops; stopped first on shutdown.</summary>
internal sealed partial class FileTailIntakeService(
    FileTailSource source,
    FileTailCursors cursors,
    ILogger<FileTailIntakeService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await cursors.Store.InitializeAsync(cancellationToken);
        await source.StartAsync(cancellationToken);
        foreach (FileTailInputStatus input in source.Snapshot())
        {
            LogTailing(logger, input.Id, input.Path);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken) =>
        await source.DisposeAsync().AsTask().WaitAsync(cancellationToken);

    /// <summary>Logs an input refused at read time: its id and reason code only.</summary>
    public static Action<string, string> Refused(ILogger logger) => (input, reason) => LogRefused(logger, input, reason);

    [LoggerMessage(EventId = 1120, Level = LogLevel.Information, Message = "File tail input {Input} reading {Path}.")]
    private static partial void LogTailing(ILogger logger, string input, string path);

    [LoggerMessage(EventId = 1121, Level = LogLevel.Warning, Message = "File tail input {Input} refused: {Reason}.")]
    private static partial void LogRefused(ILogger logger, string input, string reason);
}

/// <summary>The source cursor table inside the queue database (<c>BOWER_QUEUE_PATH</c>).</summary>
internal sealed class FileTailCursors(string queuePath)
{
    public EfSourceCursorStore Store { get; } = new(queuePath);
}
