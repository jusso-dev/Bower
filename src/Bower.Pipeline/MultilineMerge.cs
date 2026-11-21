using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Bower.Pipeline;

/// <summary>How a multi-line rule groups consecutive text lines into one record.</summary>
public enum MultilineMode
{
    /// <summary>A line matching <see cref="CustomLogMultilineRule.Pattern"/> starts a new record; non-matching lines append to the current record.</summary>
    Start,

    /// <summary>A line matching <see cref="CustomLogMultilineRule.Pattern"/> appends to the current record; non-matching lines start a new record.</summary>
    Continuation
}

/// <summary>
/// Bounded, deterministic rule for merging multi-line text records (such as Java and .NET
/// stack traces) before parsing and redaction. Limits prevent unbounded memory growth and
/// guarantee that secrets split across lines are merged before privacy detectors run.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CustomLogMultilineRule(
    MultilineMode Mode,
    string Pattern,
    int MaxLines = CustomLogMultilineRule.DefaultMaxLines,
    int MaxBytes = CustomLogMultilineRule.DefaultMaxBytes,
    int FlushTimeoutMilliseconds = CustomLogMultilineRule.DefaultFlushTimeoutMilliseconds,
    string JoinSeparator = "\n")
{
    public const int MinimumMaxLines = 2;
    public const int DefaultMaxLines = 64;
    public const int MaximumMaxLines = 256;

    public const int MinimumMaxBytes = 256;
    public const int DefaultMaxBytes = 16_384;

    /// <summary>Leaves headroom for JSON record metadata inside the 32 KiB pack parser limit.</summary>
    public const int MaximumMaxBytes = 30_720;

    public const int MinimumFlushTimeoutMilliseconds = 100;
    public const int DefaultFlushTimeoutMilliseconds = 1_000;
    public const int MaximumFlushTimeoutMilliseconds = 60_000;

    public const int MaximumPatternLength = 512;
    public const int MaximumJoinSeparatorLength = 8;

    public static void Validate(CustomLogMultilineRule rule, List<string> issues)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(issues);

        if (!Enum.IsDefined(rule.Mode))
        {
            issues.Add("Multiline mode must be Start or Continuation.");
        }

        if (string.IsNullOrWhiteSpace(rule.Pattern) || rule.Pattern.Length > MaximumPatternLength)
        {
            issues.Add($"Multiline pattern is required and cannot exceed {MaximumPatternLength} characters.");
        }
        else
        {
            try
            {
                _ = CreateSafeRegex(rule.Pattern);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
            {
                issues.Add("Multiline pattern is unsupported by the non-backtracking engine.");
            }
        }

        if (rule.MaxLines is < MinimumMaxLines or > MaximumMaxLines)
        {
            issues.Add($"Multiline maxLines must be between {MinimumMaxLines} and {MaximumMaxLines}.");
        }

        if (rule.MaxBytes is < MinimumMaxBytes or > MaximumMaxBytes)
        {
            issues.Add($"Multiline maxBytes must be between {MinimumMaxBytes} and {MaximumMaxBytes}.");
        }

        if (rule.FlushTimeoutMilliseconds is < MinimumFlushTimeoutMilliseconds or > MaximumFlushTimeoutMilliseconds)
        {
            issues.Add(
                $"Multiline flushTimeoutMilliseconds must be between {MinimumFlushTimeoutMilliseconds} and {MaximumFlushTimeoutMilliseconds}.");
        }

        if (rule.JoinSeparator is null || rule.JoinSeparator.Length > MaximumJoinSeparatorLength)
        {
            issues.Add($"Multiline joinSeparator cannot be null or exceed {MaximumJoinSeparatorLength} characters.");
        }
    }

    internal static Regex CreateSafeRegex(string pattern) =>
        new(
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            Regex.InfiniteMatchTimeout);
}

/// <summary>One complete logical record produced by <see cref="MultilineLineMerger"/>.</summary>
/// <param name="FirstLineNumber">Caller-supplied 1-based line number of the first constituent line.</param>
/// <param name="LineCount">Number of physical lines merged into <paramref name="Text"/>.</param>
/// <param name="Text">Merged text, ready for parsing and redaction.</param>
/// <param name="ReachedLimit">True when <c>maxLines</c> or <c>maxBytes</c> caused this record to flush.</param>
public sealed record MergedLineRecord(
    int FirstLineNumber,
    int LineCount,
    string Text,
    bool ReachedLimit = false);

/// <summary>
/// Stateful, bounded, deterministic multi-line record merger. Runs before parsing and
/// redaction so multi-line stack traces become one event and secrets split across lines are
/// caught as one value.
/// </summary>
public sealed class MultilineLineMerger
{
    private readonly CustomLogMultilineRule rule;
    private readonly Regex matcher;
    private readonly TimeSpan flushTimeout;
    private readonly int separatorBytes;
    private readonly StringBuilder buffer = new();
    private bool hasBuffered;
    private int bufferedLines;
    private int bufferedBytes;
    private int firstLineNumber;
    private DateTimeOffset lastLineAt;

    public MultilineLineMerger(CustomLogMultilineRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        List<string> issues = [];
        CustomLogMultilineRule.Validate(rule, issues);
        if (issues.Count != 0)
        {
            throw new InvalidDataException(string.Join(" ", issues));
        }

        this.rule = rule;
        matcher = CustomLogMultilineRule.CreateSafeRegex(rule.Pattern);
        flushTimeout = TimeSpan.FromMilliseconds(rule.FlushTimeoutMilliseconds);
        separatorBytes = Encoding.UTF8.GetByteCount(rule.JoinSeparator);
    }

    public bool HasBuffered => hasBuffered;

    public DateTimeOffset? LastLineAt => hasBuffered ? lastLineAt : null;

    /// <summary>
    /// Feeds one physical line at <paramref name="timestamp"/> and returns zero, one or two
    /// completed records (e.g. a previously buffered record flushed on timeout, boundary or
    /// start of a new record, plus the incoming line if it reaches the limit on its own).
    /// </summary>
    public IReadOnlyList<MergedLineRecord> AddLine(string line, DateTimeOffset timestamp, int lineNumber = 0)
    {
        ArgumentNullException.ThrowIfNull(line);
        List<MergedLineRecord> emitted = [];

        if (hasBuffered && timestamp - lastLineAt >= flushTimeout)
        {
            emitted.Add(TakeBuffered(reachedLimit: false));
        }

        int lineBytes = Encoding.UTF8.GetByteCount(line);
        bool matches = matcher.IsMatch(line);
        bool startsNew = rule.Mode == MultilineMode.Start ? matches : !matches;

        if (!hasBuffered)
        {
            if (lineBytes >= rule.MaxBytes)
            {
                emitted.Add(new MergedLineRecord(lineNumber, 1, line, ReachedLimit: true));
            }
            else
            {
                StartBuffer(line, lineBytes, lineNumber, timestamp);
            }

            return emitted;
        }

        if (startsNew)
        {
            emitted.Add(TakeBuffered(reachedLimit: false));
            if (lineBytes >= rule.MaxBytes)
            {
                emitted.Add(new MergedLineRecord(lineNumber, 1, line, ReachedLimit: true));
            }
            else
            {
                StartBuffer(line, lineBytes, lineNumber, timestamp);
            }

            return emitted;
        }

        int combinedBytes = bufferedBytes + separatorBytes + lineBytes;
        if (bufferedLines + 1 > rule.MaxLines || combinedBytes > rule.MaxBytes)
        {
            emitted.Add(TakeBuffered(reachedLimit: true));
            if (lineBytes >= rule.MaxBytes)
            {
                emitted.Add(new MergedLineRecord(lineNumber, 1, line, ReachedLimit: true));
            }
            else
            {
                StartBuffer(line, lineBytes, lineNumber, timestamp);
            }

            return emitted;
        }

        buffer.Append(rule.JoinSeparator);
        buffer.Append(line);
        bufferedLines++;
        bufferedBytes = combinedBytes;
        lastLineAt = timestamp;

        if (bufferedLines >= rule.MaxLines || bufferedBytes >= rule.MaxBytes)
        {
            emitted.Add(TakeBuffered(reachedLimit: true));
        }

        return emitted;
    }

    /// <summary>Flushes the buffered record when <c>flushTimeoutMilliseconds</c> has elapsed since the last line.</summary>
    public MergedLineRecord? FlushExpired(DateTimeOffset now) =>
        hasBuffered && now - lastLineAt >= flushTimeout
            ? TakeBuffered(reachedLimit: false)
            : null;

    /// <summary>Flushes any buffered record unconditionally (end of sample, rotated file drain or shutdown).</summary>
    public MergedLineRecord? Flush() =>
        hasBuffered ? TakeBuffered(reachedLimit: false) : null;

    /// <summary>Merges a finite sequence of lines (such as a sample or preview) and flushes the trailing record.</summary>
    public static IReadOnlyList<MergedLineRecord> MergeAll(
        CustomLogMultilineRule rule,
        IEnumerable<string> lines,
        DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(lines);
        MultilineLineMerger merger = new(rule);
        DateTimeOffset at = timestamp ?? DateTimeOffset.UnixEpoch;
        List<MergedLineRecord> records = [];
        int number = 0;
        foreach (string line in lines)
        {
            number++;
            records.AddRange(merger.AddLine(line, at, number));
        }

        if (merger.Flush() is { } trailing)
        {
            records.Add(trailing);
        }

        return records;
    }

    private void StartBuffer(string line, int lineBytes, int lineNumber, DateTimeOffset timestamp)
    {
        buffer.Clear();
        buffer.Append(line);
        hasBuffered = true;
        bufferedLines = 1;
        bufferedBytes = lineBytes;
        firstLineNumber = lineNumber;
        lastLineAt = timestamp;
    }

    private MergedLineRecord TakeBuffered(bool reachedLimit)
    {
        MergedLineRecord record = new(firstLineNumber, bufferedLines, buffer.ToString(), reachedLimit);
        buffer.Clear();
        hasBuffered = false;
        bufferedLines = 0;
        bufferedBytes = 0;
        firstLineNumber = 0;
        return record;
    }
}
