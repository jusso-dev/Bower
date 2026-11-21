namespace Bower.Source.Journald;

/// <summary>One raw allow-listed systemd journal entry.</summary>
public sealed record JournaldEntry(
    string Cursor,
    long RealtimeMicroseconds,
    string? Unit,
    string? SyslogIdentifier,
    string Message,
    string? Priority = null,
    string? Hostname = null);

/// <summary>
/// Platform seam for reading systemd journald entries sequentially after an opaque cursor.
/// </summary>
public interface IJournalReader : IDisposable
{
    ValueTask<IReadOnlyList<JournaldEntry>> ReadBatchAsync(
        string? afterCursor,
        int maxRecords,
        CancellationToken cancellationToken = default);
}
