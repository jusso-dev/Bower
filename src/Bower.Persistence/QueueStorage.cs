using System.Runtime.InteropServices;

namespace Bower.Persistence;

/// <summary>Bounded reason codes for <see cref="QueueCapacityExceededException"/>.</summary>
public static class QueueCapacityReasons
{
    /// <summary>The logical undelivered-byte cap or the queue's physical page/WAL ceiling.</summary>
    public const string Queue = "queue-capacity";

    /// <summary>Free space on the queue volume is below the critical watermark.</summary>
    public const string StorageCritical = "storage-critical";

    /// <summary>SQLite reported the volume full (or an I/O error while it was critically low).</summary>
    public const string StorageFull = "storage-full";
}

/// <summary>
/// Free-space watermarks for the volume that holds the queue. Each threshold is the larger
/// of an absolute byte count and a percentage of the volume, so both small and large
/// volumes keep headroom. Below warning the collector reports early warning and reclaims
/// acknowledged rows; below critical it refuses new events while delivery, acknowledgement
/// and retention keep running, so the queue drains and intake resumes by itself.
/// </summary>
public sealed record StorageWatermarkOptions
{
    public const long MinimumCriticalFreeBytes = 16L * 1024 * 1024;

    public long WarningFreeBytes { get; init; } = 1024L * 1024 * 1024;

    public int WarningFreePercent { get; init; } = 10;

    public long CriticalFreeBytes { get; init; } = 256L * 1024 * 1024;

    public int CriticalFreePercent { get; init; } = 5;

    public StorageWatermarkOptions Validate()
    {
        if (CriticalFreeBytes < MinimumCriticalFreeBytes)
        {
            throw new InvalidOperationException(
                "BOWER_STORAGE_CRITICAL_FREE_BYTES must be at least 16777216 (16 MiB) so acknowledgements can still commit.");
        }

        if (WarningFreeBytes < CriticalFreeBytes)
        {
            throw new InvalidOperationException(
                "BOWER_STORAGE_WARNING_FREE_BYTES must be at least BOWER_STORAGE_CRITICAL_FREE_BYTES.");
        }

        if (CriticalFreePercent is < 0 or > 50 || WarningFreePercent is < 0 or > 50)
        {
            throw new InvalidOperationException(
                "BOWER_STORAGE_WARNING_FREE_PERCENT and BOWER_STORAGE_CRITICAL_FREE_PERCENT must be between 0 and 50.");
        }

        if (WarningFreePercent < CriticalFreePercent)
        {
            throw new InvalidOperationException(
                "BOWER_STORAGE_WARNING_FREE_PERCENT must be at least BOWER_STORAGE_CRITICAL_FREE_PERCENT.");
        }

        return this;
    }

    public long WarningThreshold(long totalBytes) => Math.Max(WarningFreeBytes, Percent(totalBytes, WarningFreePercent));

    public long CriticalThreshold(long totalBytes) => Math.Max(CriticalFreeBytes, Percent(totalBytes, CriticalFreePercent));

    // Exact and overflow-free for any volume size.
    private static long Percent(long totalBytes, int percent) => totalBytes / 100 * percent + totalBytes % 100 * percent / 100;
}

/// <summary>Free and total bytes of one volume, as seen by the service account.</summary>
public readonly record struct DiskSpace(long FreeBytes, long TotalBytes);

/// <summary>Measures the volume holding a directory. Returns null when it cannot.</summary>
public interface IDiskSpaceProbe
{
    DiskSpace? Measure(string directory);
}

/// <summary>
/// statvfs on Unix (any path resolves to its mounted file system) and GetDiskFreeSpaceEx on
/// Windows, which, unlike <see cref="DriveInfo"/>, follows NTFS mounted folders.
/// </summary>
public sealed partial class SystemDiskSpaceProbe : IDiskSpaceProbe
{
    public static SystemDiskSpaceProbe Instance { get; } = new();

    public DiskSpace? Measure(string directory)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                string path = directory.EndsWith('\\') ? directory : directory + "\\";
                return GetDiskFreeSpaceEx(path, out ulong available, out ulong total, out _)
                    ? new DiskSpace(checked((long)available), checked((long)total))
                    : null;
            }

            DriveInfo drive = new(directory);
            return new DiskSpace(drive.AvailableFreeSpace, drive.TotalSize);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or ArgumentException or OverflowException)
        {
            return null;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetDiskFreeSpaceEx(string directory, out ulong freeBytesAvailable, out ulong totalBytes, out ulong totalFreeBytes);
}

public enum StorageState
{
    Normal,
    Warning,
    Critical,

    /// <summary>Free space could not be measured; watermarks are not enforced until it can.</summary>
    Unknown
}

/// <summary>Watermark evaluation of the queue volume. Metadata only.</summary>
public sealed record StorageWatermarkSnapshot(
    StorageState State,
    DateTimeOffset ObservedAt,
    long? FreeBytes,
    long? TotalBytes,
    long? WarningThresholdBytes,
    long? CriticalThresholdBytes,
    DateTimeOffset? StateChangedAt,
    long WarningTransitions,
    long CriticalTransitions)
{
    public double? FreePercent => FreeBytes is { } free && TotalBytes is > 0 and { } total
        ? Math.Round(free * 100.0 / total, 2)
        : null;

    public static string Name(StorageState state) => state switch
    {
        StorageState.Normal => "normal",
        StorageState.Warning => "warning",
        StorageState.Critical => "critical",
        _ => "unknown"
    };
}

/// <summary>
/// Free-space watermarks for the queue directory. Measures at most once per
/// <see cref="SampleInterval"/> (intake calls this for every insert) and applies hysteresis:
/// a state is left only once free space clears its threshold by
/// <see cref="HysteresisBytes"/>, so intake does not flap at the boundary.
/// </summary>
public sealed class StorageGuard
{
    private readonly string directory;
    private readonly IDiskSpaceProbe probe;
    private readonly TimeProvider clock;
    private readonly Lock gate = new();
    private StorageWatermarkSnapshot current;
    private DateTimeOffset nextSample = DateTimeOffset.MinValue;

    public StorageGuard(
        string queuePath,
        StorageWatermarkOptions options,
        IDiskSpaceProbe? probe = null,
        TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(queuePath);
        ArgumentNullException.ThrowIfNull(options);
        Options = options.Validate();
        directory = Path.GetDirectoryName(Path.GetFullPath(queuePath)) ?? Path.GetFullPath(".");
        this.probe = probe ?? SystemDiskSpaceProbe.Instance;
        this.clock = clock ?? TimeProvider.System;
        current = new StorageWatermarkSnapshot(StorageState.Unknown, this.clock.GetUtcNow(), null, null, null, null, null, 0, 0);
    }

    public StorageWatermarkOptions Options { get; }

    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);

    public static long HysteresisBytes(long totalBytes) => Math.Max(16L * 1024 * 1024, totalBytes / 100);

    /// <summary>The latest evaluation, refreshed when older than the sample interval or when forced.</summary>
    public StorageWatermarkSnapshot Evaluate(bool force = false)
    {
        lock (gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (!force && now < nextSample)
            {
                return current;
            }

            nextSample = now + SampleInterval;
            DiskSpace? measured = probe.Measure(directory);
            StorageState state = measured is { } space ? Classify(space, current.State) : StorageState.Unknown;
            bool changed = state != current.State;
            current = new StorageWatermarkSnapshot(
                state,
                now,
                measured?.FreeBytes,
                measured?.TotalBytes,
                measured is { } warning ? Options.WarningThreshold(warning.TotalBytes) : null,
                measured is { } critical ? Options.CriticalThreshold(critical.TotalBytes) : null,
                changed ? now : current.StateChangedAt,
                current.WarningTransitions + (changed && state == StorageState.Warning ? 1 : 0),
                current.CriticalTransitions + (changed && state == StorageState.Critical ? 1 : 0));
            return current;
        }
    }

    /// <summary>Refuses an insert while the volume is below the critical watermark.</summary>
    public void ThrowIfCritical()
    {
        StorageWatermarkSnapshot snapshot = Evaluate();
        if (snapshot.State == StorageState.Critical)
        {
            throw new QueueCapacityExceededException(
                snapshot.CriticalThresholdBytes ?? 0,
                snapshot.FreeBytes ?? 0,
                0,
                QueueCapacityReasons.StorageCritical);
        }
    }

    private StorageState Classify(DiskSpace space, StorageState previous)
    {
        long critical = Options.CriticalThreshold(space.TotalBytes);
        long warning = Options.WarningThreshold(space.TotalBytes);
        long margin = HysteresisBytes(space.TotalBytes);
        if (space.FreeBytes < critical || (previous == StorageState.Critical && space.FreeBytes < critical + margin))
        {
            return StorageState.Critical;
        }

        if (space.FreeBytes < warning
            || ((previous is StorageState.Warning or StorageState.Critical) && space.FreeBytes < warning + margin))
        {
            return StorageState.Warning;
        }

        return StorageState.Normal;
    }
}

/// <summary>
/// Physical queue files and SQLite page use. <see cref="MaximumPages"/> is the page ceiling
/// (<c>max_page_count</c>); retained acknowledged rows count against it until retention.
/// </summary>
public sealed record QueueStorageSnapshot(
    long DatabaseBytes,
    long WalBytes,
    long SharedMemoryBytes,
    long PageSize,
    long PageCount,
    long FreePages,
    long MaximumPages,
    long MaximumUndeliveredBytes,
    long MaximumStorageBytes)
{
    public long FileBytes => DatabaseBytes + WalBytes + SharedMemoryBytes;

    public long UsedPages => Math.Max(0, PageCount - FreePages);

    public double PageUtilisationPercent => MaximumPages <= 0 ? 0 : Math.Round(UsedPages * 100.0 / MaximumPages, 2);
}
