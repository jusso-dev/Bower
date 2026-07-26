using System.Text;
using Bower.Abstractions;

namespace Bower.Output.AmaSpool;

public sealed class AmaSpoolOutput : IOutputAdapter
{
    private readonly AmaSpoolOptions options;
    private long sequence;

    public AmaSpoolOutput(AmaSpoolOptions options)
    {
        options.Validate();
        this.options = options;
        Directory.CreateDirectory(options.ActiveDirectory);
        Directory.CreateDirectory(options.ReadyDirectory);
        SetDirectoryPermissions(options.ActiveDirectory);
        SetDirectoryPermissions(options.ReadyDirectory);
    }

    public string Id => options.Id;

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        if (events.Count == 0)
        {
            return new DeliveryResult([], [], null);
        }

        List<string> acknowledged = [];
        List<DeliveryFailure> failures = [];
        List<QueuedEvent> currentFile = [];
        long currentBytes = 0;

        foreach (QueuedEvent item in events)
        {
            int recordBytes = Encoding.UTF8.GetByteCount(item.Payload) + 1;
            if (recordBytes > options.MaximumFileBytes)
            {
                failures.Add(new DeliveryFailure(
                    item.EventId,
                    "record-exceeds-ama-file-limit",
                    false,
                    null));
                continue;
            }

            if (currentFile.Count > 0 && currentBytes + recordBytes > options.MaximumFileBytes)
            {
                await WriteFileAsync(currentFile, cancellationToken);
                acknowledged.AddRange(currentFile.Select(value => value.EventId));
                currentFile.Clear();
                currentBytes = 0;
            }

            currentFile.Add(item);
            currentBytes += recordBytes;
        }

        if (currentFile.Count > 0)
        {
            await WriteFileAsync(currentFile, cancellationToken);
            acknowledged.AddRange(currentFile.Select(value => value.EventId));
        }

        string? acknowledgement = acknowledged.Count == 0
            ? null
            : $"ama-spool:{options.CollectorId}:{Volatile.Read(ref sequence)}";
        return new DeliveryResult(acknowledged, failures, acknowledgement);
    }

    private async Task WriteFileAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken)
    {
        long fileSequence = Interlocked.Increment(ref sequence);
        string stem =
            $"{Sanitize(options.CollectorId)}-{Sanitize(options.StreamName)}-{fileSequence:D20}";
        string temporaryPath = Path.Combine(options.ActiveDirectory, $"{stem}.tmp");
        string readyPath = Path.Combine(options.ReadyDirectory, $"{stem}.jsonl");

        FileStreamOptions streamOptions = new()
        {
            Access = FileAccess.Write,
            Mode = FileMode.CreateNew,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows())
        {
            streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        await using (FileStream stream = new(temporaryPath, streamOptions))
        await using (StreamWriter writer = new(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            writer.NewLine = "\n";
            foreach (QueuedEvent item in events)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await writer.WriteLineAsync(item.Payload.AsMemory(), cancellationToken);
            }

            await writer.FlushAsync(cancellationToken);
            stream.Flush(true);
        }

        File.Move(temporaryPath, readyPath);
    }

    private static string Sanitize(string value)
    {
        char[] safe = value
            .Select(character => char.IsLetterOrDigit(character) || character is '-' or '_'
                ? character
                : '_')
            .ToArray();
        return new string(safe);
    }

    private static void SetDirectoryPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }
}

public sealed record AmaSpoolOptions
{
    public required string Id { get; init; }

    public required string CollectorId { get; init; }

    public required string StreamName { get; init; }

    public required string ActiveDirectory { get; init; }

    public required string ReadyDirectory { get; init; }

    public long MaximumFileBytes { get; init; } = 10 * 1024 * 1024;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(CollectorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(StreamName);
        ArgumentException.ThrowIfNullOrWhiteSpace(ActiveDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(ReadyDirectory);
        if (Path.GetFullPath(ActiveDirectory) == Path.GetFullPath(ReadyDirectory))
        {
            throw new ArgumentException("Active and ready directories must differ.");
        }

        if (MaximumFileBytes < 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumFileBytes));
        }
    }
}
