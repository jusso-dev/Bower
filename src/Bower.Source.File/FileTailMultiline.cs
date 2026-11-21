using System.Text;
using System.Text.RegularExpressions;

namespace Bower.Source.File;

/// <summary>
/// Multi-line merge rule applied to a <c>text</c> file-tail input when its routed signed pack
/// parser configures <c>multiline</c>. Kept independent of <c>Bower.Pipeline</c> so the file
/// source keeps its minimal dependency surface.
/// </summary>
public sealed record FileTailMultilineOptions(
    bool MatchStart,
    string Pattern,
    int MaxLines = 64,
    int MaxBytes = 16_384,
    int FlushTimeoutMilliseconds = 1_000,
    string JoinSeparator = "\n")
{
    public Regex CreateRegex() =>
        new(
            Pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            Regex.InfiniteMatchTimeout);
}

/// <summary>
/// One flushed multi-line (or single-line) event ready to be built into a <see cref="FileTailRecord"/>
/// and submitted. <see cref="OriginCursor"/> is the durable cursor before its first line (used for
/// backpressure/error rewind); <see cref="EndCursor"/> is the cursor after its last line (committed
/// only once this event is durably enqueued or definitively dropped).
/// </summary>
internal sealed record FileTailMergedEvent(
    FileTailLine Line,
    FileTailCursor OriginCursor,
    FileTailCursor EndCursor,
    int SourceLines,
    long SourceBytes);

/// <summary>
/// Per-input in-memory multi-line accumulator for <see cref="FileTailSource"/>. While lines are
/// buffered here, the durable SQLite cursor stays at <see cref="OriginCursor"/> so a crash before
/// flush replays from the first line of the multi-line event without loss or duplication.
/// </summary>
internal sealed class FileTailMultilineBuffer
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly FileTailMultilineOptions options;
    private readonly Regex matcher;
    private readonly byte[] separatorBytes;
    private readonly TimeSpan flushTimeout;

    private readonly List<byte[]> parts = [];
    private FileTailCursor? originCursor;
    private FileTailCursor? endCursor;
    private string? fingerprint;
    private long firstStartOffset;
    private long lastEndOffset;
    private long sourceBytes;
    private int mergedBytes;
    private DateTimeOffset lastLineAt;

    public FileTailMultilineBuffer(FileTailMultilineOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.options = options;
        matcher = options.CreateRegex();
        separatorBytes = Encoding.UTF8.GetBytes(options.JoinSeparator);
        flushTimeout = TimeSpan.FromMilliseconds(options.FlushTimeoutMilliseconds);
    }

    public bool HasBuffered => parts.Count > 0;

    /// <summary>The durable cursor before the first buffered line, or null when empty.</summary>
    public FileTailCursor? OriginCursor => originCursor;

    /// <summary>The in-memory read cursor after the last buffered line, or null when empty.</summary>
    public FileTailCursor? ReadCursor => endCursor;

    /// <summary>The file fingerprint of the buffered lines, or null when empty.</summary>
    public string? Fingerprint => fingerprint;

    public bool IsExpired(DateTimeOffset now) =>
        parts.Count > 0 && now - lastLineAt >= flushTimeout;

    /// <summary>Discards buffered state (for example on backpressure rewind or cursor reset).</summary>
    public void Clear()
    {
        parts.Clear();
        originCursor = null;
        endCursor = null;
        fingerprint = null;
        firstStartOffset = 0;
        lastEndOffset = 0;
        sourceBytes = 0;
        mergedBytes = 0;
    }

    /// <summary>Flushes the buffered lines as one merged <see cref="FileTailMergedEvent"/>, or null when empty.</summary>
    public FileTailMergedEvent? Flush()
    {
        if (parts.Count == 0)
        {
            return null;
        }

        byte[] joined = JoinParts();
        FileTailLine merged = new(joined, fingerprint!, firstStartOffset, lastEndOffset);
        FileTailMergedEvent result = new(merged, originCursor!, endCursor!, parts.Count, sourceBytes);
        Clear();
        return result;
    }

    /// <summary>
    /// Feeds one non-empty, non-oversized line into the buffer. Returns zero, one or two flushed
    /// events; invalid UTF-8 flushes any pending event first and emits the bad line standalone so
    /// <see cref="FileTailRecord.TryBuild"/> counts it as malformed without corrupting the buffer.
    /// </summary>
    public IReadOnlyList<FileTailMergedEvent> AddLine(
        FileTailLine line,
        FileTailCursor lineOrigin,
        FileTailCursor lineEnd,
        DateTimeOffset now)
    {
        List<FileTailMergedEvent> emitted = [];

        if (parts.Count > 0 && (!string.Equals(fingerprint, line.Fingerprint, StringComparison.Ordinal) || IsExpired(now)))
        {
            emitted.Add(Flush()!);
        }

        string text;
        try
        {
            text = StrictUtf8.GetString(line.Bytes);
        }
        catch (DecoderFallbackException)
        {
            if (parts.Count > 0)
            {
                emitted.Add(Flush()!);
            }

            emitted.Add(new FileTailMergedEvent(line, lineOrigin, lineEnd, 1, line.EndOffset - line.StartOffset));
            return emitted;
        }

        bool matches = matcher.IsMatch(text);
        bool startsNew = options.MatchStart ? matches : !matches;

        if (parts.Count == 0)
        {
            if (line.Bytes.Length >= options.MaxBytes)
            {
                emitted.Add(new FileTailMergedEvent(line, lineOrigin, lineEnd, 1, line.EndOffset - line.StartOffset));
            }
            else
            {
                Start(line, lineOrigin, lineEnd, now);
            }

            return emitted;
        }

        if (startsNew)
        {
            emitted.Add(Flush()!);
            if (line.Bytes.Length >= options.MaxBytes)
            {
                emitted.Add(new FileTailMergedEvent(line, lineOrigin, lineEnd, 1, line.EndOffset - line.StartOffset));
            }
            else
            {
                Start(line, lineOrigin, lineEnd, now);
            }

            return emitted;
        }

        int combinedBytes = mergedBytes + separatorBytes.Length + line.Bytes.Length;
        if (parts.Count + 1 > options.MaxLines || combinedBytes > options.MaxBytes)
        {
            emitted.Add(Flush()!);
            if (line.Bytes.Length >= options.MaxBytes)
            {
                emitted.Add(new FileTailMergedEvent(line, lineOrigin, lineEnd, 1, line.EndOffset - line.StartOffset));
            }
            else
            {
                Start(line, lineOrigin, lineEnd, now);
            }

            return emitted;
        }

        parts.Add(line.Bytes);
        endCursor = lineEnd;
        lastEndOffset = line.EndOffset;
        sourceBytes += line.EndOffset - line.StartOffset;
        mergedBytes = combinedBytes;
        lastLineAt = now;

        if (parts.Count >= options.MaxLines || mergedBytes >= options.MaxBytes)
        {
            emitted.Add(Flush()!);
        }

        return emitted;
    }

    private void Start(FileTailLine line, FileTailCursor lineOrigin, FileTailCursor lineEnd, DateTimeOffset now)
    {
        parts.Clear();
        parts.Add(line.Bytes);
        originCursor = lineOrigin;
        endCursor = lineEnd;
        fingerprint = line.Fingerprint;
        firstStartOffset = line.StartOffset;
        lastEndOffset = line.EndOffset;
        sourceBytes = line.EndOffset - line.StartOffset;
        mergedBytes = line.Bytes.Length;
        lastLineAt = now;
    }

    private byte[] JoinParts()
    {
        if (parts.Count == 1)
        {
            return parts[0];
        }

        byte[] output = new byte[mergedBytes];
        int offset = 0;
        for (int index = 0; index < parts.Count; index++)
        {
            if (index > 0 && separatorBytes.Length > 0)
            {
                Buffer.BlockCopy(separatorBytes, 0, output, offset, separatorBytes.Length);
                offset += separatorBytes.Length;
            }

            byte[] part = parts[index];
            Buffer.BlockCopy(part, 0, output, offset, part.Length);
            offset += part.Length;
        }

        return output;
    }
}
