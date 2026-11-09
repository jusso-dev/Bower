using System.Globalization;
using System.Text.RegularExpressions;
using Bower.Abstractions;

namespace Bower.Collector;

/// <summary>
/// Last start's recovery result for <c>/v1/status</c>. Metadata only.
/// </summary>
/// <param name="UncleanShutdown">The previous run did not stop cleanly (its run marker was still present).</param>
/// <param name="PreviousStartedAt">Start time recorded by the run that did not stop cleanly.</param>
/// <param name="LedgerIntact">Queue ledger verification after an unclean shutdown; null when not checked.</param>
/// <param name="LedgerIssues">Number of ledger issues found; 0 when intact or not checked.</param>
/// <param name="TemporaryFilesRemoved">Abandoned Bower temporary files removed at start.</param>
public sealed record CrashRecoveryStatus(
    bool UncleanShutdown,
    DateTimeOffset? PreviousStartedAt,
    bool? LedgerIntact,
    int LedgerIssues,
    int TemporaryFilesRemoved,
    DateTimeOffset CheckedAt);

/// <summary>
/// Unclean-shutdown detection and abandoned temporary-file cleanup (#138).
/// A run marker (<c>collector.running</c>) is written beside the queue at start and removed on a
/// clean stop. If it is still there at the next start, the previous process was killed or lost
/// power: the queue ledger is verified and the result is logged and reported. SQLite's own WAL
/// recovery restores committed transactions; this only proves the hash chain afterwards.
/// </summary>
public static partial class CrashRecovery
{
    public const string MarkerFileName = "collector.running";

    /// <summary>Temporary files older than this are abandoned (a live write takes milliseconds).</summary>
    public static readonly TimeSpan TemporaryFileAge = TimeSpan.FromHours(1);

    public const int MaximumTemporaryFilesPerSweep = 1_000;

    public static string MarkerPath(string queuePath) =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(queuePath)) ?? ".", MarkerFileName);

    /// <summary>
    /// Reads a leftover marker, then writes this run's. Returns the previous run's start time
    /// when it did not stop cleanly; <c>DateTimeOffset.MinValue</c> when the marker was unreadable.
    /// </summary>
    public static DateTimeOffset? BeginRun(string markerPath, DateTimeOffset now)
    {
        DateTimeOffset? previous = null;
        if (File.Exists(markerPath))
        {
            string text = SafeRead(markerPath);
            previous = DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset at)
                ? at
                : DateTimeOffset.MinValue;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
        File.WriteAllText(markerPath, now.UtcDateTime.ToString("O", CultureInfo.InvariantCulture) + "\n");
        return previous;
    }

    /// <summary>Removes the marker on a clean stop. Never throws.</summary>
    public static void EndRun(string markerPath)
    {
        try
        {
            File.Delete(markerPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The next start reports an unclean shutdown, which is the safe direction.
        }
    }

    /// <summary>
    /// Deletes Bower's own abandoned atomic-write temporaries (<c>.NAME.GUID.tmp</c>, written by
    /// the collector id, management credential, command ledger and privacy profile cache) older
    /// than <see cref="TemporaryFileAge"/>, in the given directories only, not recursively.
    /// Never touches any other file. Returns the number removed.
    /// </summary>
    public static int SweepTemporaryFiles(IEnumerable<string> directories, DateTimeOffset now)
    {
        int removed = 0;
        foreach (string directory in directories.Distinct(StringComparer.Ordinal))
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            foreach (string path in Directory.EnumerateFiles(directory, ".*.tmp", SearchOption.TopDirectoryOnly))
            {
                if (removed >= MaximumTemporaryFilesPerSweep)
                {
                    return removed;
                }

                if (!AtomicTemporary().IsMatch(Path.GetFileName(path)))
                {
                    continue;
                }

                try
                {
                    FileInfo file = new(path);
                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0
                        || now - new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero) < TemporaryFileAge)
                    {
                        continue;
                    }

                    file.Delete();
                    removed++;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // Left for the next sweep.
                }
            }
        }

        return removed;
    }

    /// <summary>Verifies the ledger after an unclean shutdown; otherwise reports a clean start.</summary>
    public static Task<CrashRecoveryStatus> RecoverAsync(
        IDurableEventStore queue,
        DateTimeOffset? previousStartedAt,
        int temporaryFilesRemoved,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(queue);
        return RecoverAsync(queue.VerifyLedgerAsync, previousStartedAt, temporaryFilesRemoved, now, cancellationToken);
    }

    public static async Task<CrashRecoveryStatus> RecoverAsync(
        Func<CancellationToken, Task<LedgerVerification>> verifyLedger,
        DateTimeOffset? previousStartedAt,
        int temporaryFilesRemoved,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verifyLedger);
        if (previousStartedAt is null)
        {
            return new CrashRecoveryStatus(false, null, null, 0, temporaryFilesRemoved, now);
        }

        LedgerVerification ledger = await verifyLedger(cancellationToken);
        return new CrashRecoveryStatus(
            true,
            previousStartedAt == DateTimeOffset.MinValue ? null : previousStartedAt,
            ledger.Intact,
            ledger.Issues.Count,
            temporaryFilesRemoved,
            now);
    }

    private static string SafeRead(string path)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[64];
            int read = stream.Read(buffer);
            return System.Text.Encoding.ASCII.GetString(buffer, 0, read).Trim();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    // .<name>.<32 hex>.tmp, exactly as the collector's atomic writers name them.
    [GeneratedRegex(@"^\.[A-Za-z0-9._-]{1,128}\.[0-9a-f]{32}\.tmp$", RegexOptions.CultureInvariant)]
    private static partial Regex AtomicTemporary();
}

internal static partial class CrashRecoveryLog
{
    [LoggerMessage(EventId = 1600, Level = LogLevel.Warning,
        Message = "Previous collector run did not stop cleanly (started {PreviousStartedAt}). Queue ledger intact: {Intact}, issues: {Issues}.")]
    public static partial void Unclean(ILogger logger, string previousStartedAt, bool intact, int issues);

    [LoggerMessage(EventId = 1601, Level = LogLevel.Error,
        Message = "Queue ledger verification failed after an unclean shutdown: {Issues} issue(s). Run 'bower queue verify' and see docs/operations/queue-v5-durability.md.")]
    public static partial void LedgerBroken(ILogger logger, int issues);

    [LoggerMessage(EventId = 1602, Level = LogLevel.Information,
        Message = "Removed {Count} abandoned temporary file(s) from collector state directories.")]
    public static partial void TemporaryFilesRemoved(ILogger logger, int count);
}

/// <summary>Holds the last start's <see cref="CrashRecoveryStatus"/> for <c>/v1/status</c>.</summary>
public sealed class CrashRecoveryState
{
    public CrashRecoveryStatus? Last { get; set; }
}
