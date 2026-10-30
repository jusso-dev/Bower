using System.Globalization;
using System.Text;
using Bower.Abstractions;

namespace Bower.Output.AmaSpool;

public sealed class AmaSpoolOutput : IOutputAdapter
{
    private const int SequenceDigits = 20;

    private readonly AmaSpoolOptions options;
    private readonly string filePrefix;
    private long sequence;

    public AmaSpoolOutput(AmaSpoolOptions options)
    {
        options.Validate();
        this.options = options;
        filePrefix = $"{Sanitize(options.CollectorId)}-{Sanitize(options.StreamName)}-";
        Directory.CreateDirectory(options.ActiveDirectory);
        Directory.CreateDirectory(options.ReadyDirectory);
        SetDirectoryPermissions(options.ActiveDirectory);
        SetDirectoryPermissions(options.ReadyDirectory);

        // Continue numbering after every file a previous process left behind, so a restart
        // never reuses the name of a ready file AMA has not consumed yet (File.Move would
        // fail on every retry) or of a leftover temporary file (CreateNew would).
        sequence = Math.Max(
            HighestSequence(options.ReadyDirectory, ".jsonl"),
            HighestSequence(options.ActiveDirectory, ".tmp"));
        RemoveStaleTemporaryFiles();
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

        try
        {
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
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested && acknowledged.Count > 0)
        {
            // A deadline can interrupt a later file after earlier files were durably
            // published. Return those known acknowledgements so the worker does not
            // re-spool them under fresh sequence numbers. Only unfinished events retry.
            HashSet<string> settled = new(acknowledged.Concat(failures.Select(item => item.EventId)), StringComparer.Ordinal);
            failures.AddRange(events.Where(item => !settled.Contains(item.EventId)).Select(item =>
                new DeliveryFailure(item.EventId, "destination-ama-cancelled", true, null)));
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
        string stem = $"{filePrefix}{fileSequence:D20}";
        string temporaryPath = Path.Combine(options.ActiveDirectory, $"{stem}.tmp");
        string readyPath = Path.Combine(options.ReadyDirectory, $"{stem}.jsonl");

        FileStreamOptions streamOptions = new()
        {
            Access = FileAccess.Write,
            Mode = FileMode.CreateNew,
            Share = FileShare.None,
            // No WriteThrough: it made every 4 KiB buffer flush a synchronous disk write.
            // Durability comes from the single fsync (Flush(true)) before the atomic rename,
            // so a ready file is still complete and on disk before it is acknowledged.
            Options = FileOptions.Asynchronous,
            BufferSize = 64 * 1024
        };
        if (!OperatingSystem.IsWindows())
        {
            streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        FileStream stream = new(temporaryPath, streamOptions);
        try
        {
            await using (stream)
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
        catch
        {
            // The events stay unacknowledged and are retried under a new sequence number;
            // never leave a partial temporary file behind.
            TryDelete(temporaryPath);
            throw;
        }

        // The rename is durable only once the ready directory itself is on disk.
        DirectorySync.Flush(options.ReadyDirectory);
    }

    /// <summary>Highest sequence among this output's files with the given extension.</summary>
    private long HighestSequence(string directory, string extension)
    {
        long highest = 0;
        foreach (string path in Directory.EnumerateFiles(directory, $"{filePrefix}*"))
        {
            if (TryParseSequence(Path.GetFileName(path), extension, out long value) && value > highest)
            {
                highest = value;
            }
        }

        return highest;
    }

    private bool TryParseSequence(string fileName, string extension, out long value)
    {
        value = 0;
        if (fileName.Length != filePrefix.Length + SequenceDigits + extension.Length
            || !fileName.StartsWith(filePrefix, StringComparison.Ordinal)
            || !fileName.EndsWith(extension, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> digits = fileName.AsSpan(filePrefix.Length, SequenceDigits);
        return long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// Temporary files left by a crash hold events that were never acknowledged (the
    /// acknowledgement follows the rename), so the queue redelivers them; the files only
    /// waste space.
    /// </summary>
    private void RemoveStaleTemporaryFiles()
    {
        foreach (string path in Directory.EnumerateFiles(options.ActiveDirectory, $"{filePrefix}*"))
        {
            if (TryParseSequence(Path.GetFileName(path), ".tmp", out _))
            {
                TryDelete(path);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best effort: numbering never reuses the name.
        }
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
        // "/a/b" and "/a/b/" are the same directory.
        if (string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(ActiveDirectory)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(ReadyDirectory)),
                StringComparison.Ordinal))
        {
            throw new ArgumentException("Active and ready directories must differ.");
        }

        if (MaximumFileBytes < 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumFileBytes));
        }
    }
}
