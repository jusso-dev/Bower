using System.Globalization;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;

namespace Bower.Source.Journald;

/// <summary>One bounded journald record ready for signed pack parsing.</summary>
public sealed record JournaldRecord(
    string SubscriptionName,
    string Cursor,
    string RecordJson);

/// <summary>Outcome counters of one bounded poll cycle. Metadata only.</summary>
public sealed record JournaldPollResult(
    int Read,
    int Delivered,
    int FilteredOut,
    int RejectedInvalid,
    int RejectedOversized,
    string? CommittedCursor,
    bool StoppedOnBackpressure);

/// <summary>
/// Allow-listed, cursor-durable systemd journald source. Produces bounded JSON records
/// compatible with <c>packs/linux-journald-ssh</c> and commits the cursor strictly after
/// caller acknowledgment (at-least-once semantics).
/// </summary>
public sealed class JournaldSource
{
    private readonly JournaldSourceOptions options;
    private readonly IJournalReader reader;
    private readonly ISourceCursorStore cursorStore;
    private readonly TimeProvider clock;
    private readonly HashSet<string> allowedUnits;
    private readonly HashSet<string> allowedIdentifiers;
    private readonly string cursorKey;

    public JournaldSource(
        JournaldSourceOptions options,
        IJournalReader reader,
        ISourceCursorStore cursorStore,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(cursorStore);
        options.Validate();

        this.options = options;
        this.reader = reader;
        this.cursorStore = cursorStore;
        this.clock = clock ?? TimeProvider.System;
        allowedUnits = new HashSet<string>(options.Units, StringComparer.Ordinal);
        allowedIdentifiers = new HashSet<string>(options.Identifiers, StringComparer.Ordinal);
        cursorKey = $"journald:{options.SubscriptionName}";
    }

    public string CursorKey => cursorKey;

    /// <summary>
    /// Reads at most <see cref="JournaldSourceOptions.MaxBatchSize"/> entries after the stored
    /// cursor, filters strictly by allow-list, invokes <paramref name="onRecord"/>, and commits
    /// the cursor only for acknowledged or definitively dropped entries.
    /// </summary>
    public async Task<JournaldPollResult> PollOnceAsync(
        Func<JournaldRecord, CancellationToken, Task<bool>> onRecord,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(onRecord);
        cancellationToken.ThrowIfCancellationRequested();

        SourceCursorSnapshot? snapshot = await cursorStore.ReadAsync(cursorKey, cancellationToken);
        string? currentCursor = snapshot?.Value;
        long expectedVersion = snapshot?.Version ?? 0;

        IReadOnlyList<JournaldEntry> batch = await reader.ReadBatchAsync(
            currentCursor,
            options.MaxBatchSize,
            cancellationToken);

        int delivered = 0;
        int filteredOut = 0;
        int rejectedInvalid = 0;
        int rejectedOversized = 0;
        string? lastCommitCursor = null;
        bool backpressure = false;

        foreach (JournaldEntry entry in batch)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(entry.Cursor) || entry.Cursor.Length > 512)
            {
                rejectedInvalid++;
                continue;
            }

            if (!IsAllowed(entry))
            {
                filteredOut++;
                lastCommitCursor = entry.Cursor;
                continue;
            }

            if (entry.RealtimeMicroseconds <= 0 || entry.Message is null)
            {
                rejectedInvalid++;
                lastCommitCursor = entry.Cursor;
                continue;
            }

            string recordJson = SerializeJournalJson(entry);
            if (Encoding.UTF8.GetByteCount(recordJson) > options.MaxRecordBytes)
            {
                rejectedOversized++;
                lastCommitCursor = entry.Cursor;
                continue;
            }

            bool acknowledged = await onRecord(
                new JournaldRecord(options.SubscriptionName, entry.Cursor, recordJson),
                cancellationToken);
            if (!acknowledged)
            {
                backpressure = true;
                break;
            }

            delivered++;
            lastCommitCursor = entry.Cursor;
        }

        if (lastCommitCursor is not null)
        {
            await cursorStore.TryAdvanceAsync(
                cursorKey,
                expectedVersion,
                lastCommitCursor,
                clock.GetUtcNow(),
                cancellationToken);
        }

        return new JournaldPollResult(
            batch.Count,
            delivered,
            filteredOut,
            rejectedInvalid,
            rejectedOversized,
            lastCommitCursor,
            backpressure);
    }

    internal bool IsAllowed(JournaldEntry entry)
    {
        bool unitMatch = !string.IsNullOrWhiteSpace(entry.Unit) && allowedUnits.Contains(entry.Unit);
        bool identifierMatch = !string.IsNullOrWhiteSpace(entry.SyslogIdentifier) && allowedIdentifiers.Contains(entry.SyslogIdentifier);
        return unitMatch || identifierMatch;
    }

    internal static string SerializeJournalJson(JournaldEntry entry)
    {
        using MemoryStream buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("__CURSOR", entry.Cursor);
            writer.WriteString("__REALTIME_TIMESTAMP", entry.RealtimeMicroseconds.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrWhiteSpace(entry.Unit))
            {
                writer.WriteString("_SYSTEMD_UNIT", entry.Unit);
            }

            if (!string.IsNullOrWhiteSpace(entry.SyslogIdentifier))
            {
                writer.WriteString("SYSLOG_IDENTIFIER", entry.SyslogIdentifier);
            }

            writer.WriteString("MESSAGE", entry.Message);
            if (!string.IsNullOrWhiteSpace(entry.Priority))
            {
                writer.WriteString("PRIORITY", entry.Priority);
            }

            if (!string.IsNullOrWhiteSpace(entry.Hostname))
            {
                writer.WriteString("_HOSTNAME", entry.Hostname);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
