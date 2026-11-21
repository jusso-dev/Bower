using System.Runtime.InteropServices;
using System.Text;

namespace Bower.Source.Journald;

/// <summary>
/// Linux <c>libsystemd.so.0</c> journal reader using Native AOT-compatible <see cref="LibraryImportAttribute"/>.
/// Applies unit and <c>SYSLOG_IDENTIFIER</c> matches at the journal API boundary before reading messages.
/// </summary>
public sealed partial class LibSystemdJournalReader : IJournalReader
{
    private const string LibSystemd = "libsystemd.so.0";
    private const int SdJournalLocalOnly = 1 << 0;
    private const int SdJournalSystem = 1 << 2;

    private readonly JournaldSourceOptions options;
    private IntPtr journal;
    private bool disposed;

    public LibSystemdJournalReader(JournaldSourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("LibSystemdJournalReader requires Linux with libsystemd.so.0.");
        }

        this.options = options;
        int rc = SdJournalOpen(out journal, SdJournalLocalOnly | SdJournalSystem);
        if (rc < 0 || journal == IntPtr.Zero)
        {
            throw new InvalidOperationException($"sd_journal_open failed with errno {-rc}.");
        }

        try
        {
            ApplyMatches();
        }
        catch
        {
            SdJournalClose(journal);
            journal = IntPtr.Zero;
            throw;
        }
    }

    public ValueTask<IReadOnlyList<JournaldEntry>> ReadBatchAsync(
        string? afterCursor,
        int maxRecords,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        if (!string.IsNullOrWhiteSpace(afterCursor))
        {
            byte[] cursorUtf8 = Encoding.UTF8.GetBytes(afterCursor + '\0');
            int seekRc = SdJournalSeekCursor(journal, cursorUtf8);
            if (seekRc < 0)
            {
                throw new InvalidOperationException($"sd_journal_seek_cursor failed with errno {-seekRc}.");
            }

            // Advance onto the cursor entry so the loop's next() moves past it.
            _ = SdJournalNext(journal);
        }

        List<JournaldEntry> entries = new(Math.Min(maxRecords, 64));
        while (entries.Count < maxRecords)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int step = SdJournalNext(journal);
            if (step < 0)
            {
                throw new InvalidOperationException($"sd_journal_next failed with errno {-step}.");
            }

            if (step == 0)
            {
                break;
            }

            string? cursor = ReadCursor();
            if (string.IsNullOrWhiteSpace(cursor))
            {
                continue;
            }

            int timeRc = SdJournalGetRealtimeUsec(journal, out ulong usec);
            long realtime = timeRc >= 0 ? unchecked((long)usec) : 0;

            string? unit = ReadField("_SYSTEMD_UNIT");
            string? identifier = ReadField("SYSLOG_IDENTIFIER");
            string message = ReadField("MESSAGE") ?? string.Empty;
            string? priority = ReadField("PRIORITY");
            string? hostname = ReadField("_HOSTNAME");

            entries.Add(new JournaldEntry(cursor, realtime, unit, identifier, message, priority, hostname));
        }

        return ValueTask.FromResult<IReadOnlyList<JournaldEntry>>(entries);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        if (journal != IntPtr.Zero)
        {
            SdJournalClose(journal);
            journal = IntPtr.Zero;
        }
    }

    private void ApplyMatches()
    {
        bool first = true;
        foreach (string unit in options.Units)
        {
            if (!first)
            {
                CheckRc(SdJournalAddDisjunction(journal), "sd_journal_add_disjunction");
            }

            AddMatch($"_SYSTEMD_UNIT={unit}");
            first = false;
        }

        foreach (string identifier in options.Identifiers)
        {
            if (!first)
            {
                CheckRc(SdJournalAddDisjunction(journal), "sd_journal_add_disjunction");
            }

            AddMatch($"SYSLOG_IDENTIFIER={identifier}");
            first = false;
        }
    }

    private void AddMatch(string expression)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(expression);
        CheckRc(SdJournalAddMatch(journal, bytes, (nuint)bytes.Length), "sd_journal_add_match");
    }

    private unsafe string? ReadField(string fieldName)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(fieldName + '\0');
        int rc = SdJournalGetData(journal, nameBytes, out IntPtr dataPtr, out nuint length);
        if (rc < 0 || dataPtr == IntPtr.Zero || length == 0)
        {
            return null;
        }

        int capped = (int)Math.Min(length, (nuint)(options.MaxRecordBytes + fieldName.Length + 2));
        ReadOnlySpan<byte> span = new((void*)dataPtr, capped);
        int eq = span.IndexOf((byte)'=');
        if (eq < 0 || eq + 1 > span.Length)
        {
            return null;
        }

        return Encoding.UTF8.GetString(span[(eq + 1)..]);
    }

    private unsafe string? ReadCursor()
    {
        int rc = SdJournalGetCursor(journal, out IntPtr cursorPtr);
        if (rc < 0 || cursorPtr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(cursorPtr);
        }
        finally
        {
            NativeMemory.Free((void*)cursorPtr);
        }
    }

    private static void CheckRc(int rc, string function)
    {
        if (rc < 0)
        {
            throw new InvalidOperationException($"{function} failed with errno {-rc}.");
        }
    }

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_open")]
    private static partial int SdJournalOpen(out IntPtr ret, int flags);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_close")]
    private static partial void SdJournalClose(IntPtr j);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_add_match")]
    private static partial int SdJournalAddMatch(IntPtr j, ReadOnlySpan<byte> data, nuint size);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_add_disjunction")]
    private static partial int SdJournalAddDisjunction(IntPtr j);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_seek_cursor")]
    private static partial int SdJournalSeekCursor(IntPtr j, ReadOnlySpan<byte> cursor);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_next")]
    private static partial int SdJournalNext(IntPtr j);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_get_data")]
    private static partial int SdJournalGetData(IntPtr j, ReadOnlySpan<byte> field, out IntPtr data, out nuint length);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_get_cursor")]
    private static partial int SdJournalGetCursor(IntPtr j, out IntPtr cursor);

    [LibraryImport(LibSystemd, EntryPoint = "sd_journal_get_realtime_usec")]
    private static partial int SdJournalGetRealtimeUsec(IntPtr j, out ulong usec);
}
