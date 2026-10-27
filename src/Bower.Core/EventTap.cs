using System.Text;
using System.Threading.Channels;
using Bower.Contracts;

namespace Bower.Core;

/// <summary>
/// Live, bounded view of selection outcomes for <c>bower tap</c>. The earliest tap point is
/// after the privacy engine: a frame never holds a pre-redaction value. Only accepted events
/// carry content, and that content is the exact redacted payload handed to the queue;
/// every other outcome is metadata only (stage, action, event type, reasons). Nothing is
/// persisted. <see cref="Publish"/> never blocks: a session whose buffer is full or whose
/// rate allowance is spent drops the frame and counts it.
/// </summary>
public sealed class EventTap(EventTapOptions options, TimeProvider clock)
{
    public const string SchemaVersion = "bower.tap/v1";

    /// <summary>Frames a session buffers before new frames are dropped.</summary>
    public const int SessionBufferFrames = 64;

    /// <summary>Longest event type, application or environment shown in a frame.</summary>
    public const int MaximumMetadataLength = 128;

    private readonly Lock gate = new();
    private EventTapSession[] sessions = [];
    private long sessionsOpened;
    private long sessionsRefused;
    private long framesSent;
    private long framesDropped;
    private long framesRateLimited;

    public EventTapOptions Options => options;

    /// <summary>True while at least one session is open.</summary>
    public bool IsActive => Volatile.Read(ref sessions).Length > 0;

    /// <summary>Opens a session, or returns null when tap is disabled or every slot is in use.</summary>
    public EventTapSession? TryOpen(EventTapRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            if (!options.Enabled || sessions.Length >= options.MaximumSessions)
            {
                sessionsRefused++;
                return null;
            }

            EventTapSession session = new(this, request with
            {
                Limit = Math.Clamp(request.Limit, 1, options.MaximumEvents),
                Duration = request.Duration <= TimeSpan.Zero || request.Duration > options.MaximumDuration
                    ? options.MaximumDuration
                    : request.Duration,
                Sample = Math.Clamp(request.Sample, 1, EventTapRequest.MaximumSample)
            }, clock);
            sessions = [.. sessions, session];
            sessionsOpened++;
            return session;
        }
    }

    internal void Close(EventTapSession session)
    {
        lock (gate)
        {
            sessions = [.. sessions.Where(item => !ReferenceEquals(item, session))];
        }
    }

    /// <summary>
    /// Offers one final selection outcome to every open session. <paramref name="subject"/> is
    /// the redacted candidate (metadata only); <paramref name="acceptedPayload"/> is the
    /// redacted queued payload of an accepted event, or null.
    /// </summary>
    public void Publish(ProcessingResult result, SecurityEventEnvelope? subject = null, string? acceptedPayload = null)
    {
        EventTapSession[] current = Volatile.Read(ref sessions);
        if (current.Length == 0)
        {
            return;
        }

        ArgumentNullException.ThrowIfNull(result);
        EventTapRecord record = EventTapRecord.Create(
            result, subject, acceptedPayload, options.MaximumEventBytes, clock.GetUtcNow());
        foreach (EventTapSession session in current)
        {
            session.Offer(record);
        }
    }

    public EventTapSnapshot Snapshot()
    {
        lock (gate)
        {
            return new EventTapSnapshot(
                options.Enabled,
                sessions.Length,
                options.MaximumSessions,
                sessionsOpened,
                sessionsRefused,
                Interlocked.Read(ref framesSent),
                Interlocked.Read(ref framesDropped),
                Interlocked.Read(ref framesRateLimited));
        }
    }

    internal void CountSent() => Interlocked.Increment(ref framesSent);

    internal void CountDropped() => Interlocked.Increment(ref framesDropped);

    internal void CountRateLimited() => Interlocked.Increment(ref framesRateLimited);
}

/// <summary>Tap limits (BOWER_TAP_*). Defaults keep tap a debugging view, not an export path.</summary>
public sealed record EventTapOptions
{
    public bool Enabled { get; init; } = true;

    public int MaximumSessions { get; init; } = 2;

    /// <summary>Frames per second per session; frames over the allowance are dropped and counted.</summary>
    public int MaximumEventsPerSecond { get; init; } = 20;

    public TimeSpan MaximumDuration { get; init; } = TimeSpan.FromSeconds(300);

    /// <summary>Most frames one session may receive.</summary>
    public int MaximumEvents { get; init; } = 1000;

    /// <summary>Accepted events whose payload is larger are shown as metadata only.</summary>
    public int MaximumEventBytes { get; init; } = 16_384;
}

/// <summary>Where a session taps: every outcome, policy decisions only, or queued events only.</summary>
public enum TapPoint
{
    Redacted,
    Decided,
    Queued
}

/// <summary>One session's filters and caps (clamped to <see cref="EventTapOptions"/> on open).</summary>
public sealed record EventTapRequest(
    string Producer,
    TapPoint Point,
    string? Application,
    string? EventType,
    int Limit,
    TimeSpan Duration,
    int Sample)
{
    public const int DefaultLimit = 100;
    public const int MaximumSample = 10_000;
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(60);

    public static string PointName(TapPoint point) => point switch
    {
        TapPoint.Decided => "decided",
        TapPoint.Queued => "queued",
        _ => "redacted"
    };

    /// <summary>
    /// Parses a tap point. There is deliberately no <c>parsed</c> or raw point: nothing
    /// before the privacy engine can be tapped.
    /// </summary>
    public static TapPoint? ParsePoint(string? value) => value switch
    {
        null or "" or "redacted" => TapPoint.Redacted,
        "decided" => TapPoint.Decided,
        "queued" => TapPoint.Queued,
        _ => null
    };

    /// <summary>
    /// Filter values are matched exactly and written to the audit log, so they are limited to
    /// 1-128 characters from a safe set (letters, digits and <c>. _ : / @ -</c>).
    /// </summary>
    public static bool IsValidFilter(string value) =>
        value.Length is >= 1 and <= MaximumFilterLength
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or ':' or '/' or '@' or '-');

    private const int MaximumFilterLength = 128;
}

/// <summary>A final selection outcome as the tap sees it. Built only after redaction.</summary>
public sealed record EventTapRecord(
    DateTimeOffset ObservedAt,
    string Stage,
    string Action,
    bool Queued,
    bool Duplicate,
    bool Suppressed,
    string? EventType,
    string? Application,
    string? Environment,
    string? PolicyId,
    IReadOnlyList<string> Reasons,
    string? Event,
    string? EventOmitted)
{
    public const string OmittedNotAccepted = "not-accepted";
    public const string OmittedSizeCap = "size-cap";

    internal static EventTapRecord Create(
        ProcessingResult result,
        SecurityEventEnvelope? subject,
        string? acceptedPayload,
        int maximumEventBytes,
        DateTimeOffset now)
    {
        bool accepted = result.Action is DecisionAction.Accept or DecisionAction.RedactAndAccept
            && acceptedPayload is not null;
        string? content = null;
        string omitted = OmittedNotAccepted;
        if (accepted)
        {
            if (Encoding.UTF8.GetByteCount(acceptedPayload!) <= maximumEventBytes)
            {
                content = acceptedPayload;
            }
            else
            {
                omitted = OmittedSizeCap;
            }
        }

        return new EventTapRecord(
            now,
            PipelineTelemetry.StageName(result.Stage),
            PipelineTelemetry.ActionName(result.Action),
            result.Queued,
            result.Duplicate,
            result.Suppressed,
            Bounded(subject?.EventType),
            Bounded(subject?.Application?.Name),
            Bounded(subject?.Application?.Environment),
            result.PolicyDecision?.PolicyId,
            result.Reasons,
            content,
            content is null ? omitted : null);
    }

    public bool Matches(EventTapRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        bool point = request.Point switch
        {
            TapPoint.Decided => Stage == "policy",
            TapPoint.Queued => Queued,
            _ => true
        };
        return point
            && (request.Application is null || string.Equals(request.Application, Application, StringComparison.Ordinal))
            && (request.EventType is null || string.Equals(request.EventType, EventType, StringComparison.Ordinal));
    }

    private static string? Bounded(string? value) =>
        value is null || value.Length <= EventTap.MaximumMetadataLength
            ? value
            : value[..EventTap.MaximumMetadataLength];
}

/// <summary>
/// One open tap. Frames are buffered in a small bounded channel; the reader streams them.
/// Dispose to release the slot.
/// </summary>
public sealed class EventTapSession : IDisposable
{
    private readonly EventTap owner;
    private readonly TimeProvider clock;
    private readonly Channel<EventTapRecord> channel = Channel.CreateBounded<EventTapRecord>(
        new BoundedChannelOptions(EventTap.SessionBufferFrames)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    private readonly Lock bucketGate = new();
    private double tokens;
    private long refilledAt;
    private long matched;
    private long buffered;
    private long sent;
    private long dropped;
    private long rateLimited;
    private int disposed;

    internal EventTapSession(EventTap owner, EventTapRequest request, TimeProvider clock)
    {
        this.owner = owner;
        this.clock = clock;
        Request = request;
        Id = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        OpenedAt = clock.GetUtcNow();
        tokens = owner.Options.MaximumEventsPerSecond;
        refilledAt = clock.GetUtcNow().UtcTicks;
    }

    public string Id { get; }

    public EventTapRequest Request { get; }

    public DateTimeOffset OpenedAt { get; }

    public ChannelReader<EventTapRecord> Reader => channel.Reader;

    public long Sent => Interlocked.Read(ref sent);

    public long Dropped => Interlocked.Read(ref dropped);

    public long RateLimited => Interlocked.Read(ref rateLimited);

    /// <summary>Records one frame written to the client.</summary>
    public void MarkSent()
    {
        Interlocked.Increment(ref sent);
        owner.CountSent();
    }

    internal void Offer(EventTapRecord record)
    {
        if (!record.Matches(Request))
        {
            return;
        }

        // Deterministic 1-in-N sampling of matching outcomes.
        long sequence = Interlocked.Increment(ref matched);
        if ((sequence - 1) % Request.Sample != 0 || Interlocked.Read(ref buffered) >= Request.Limit)
        {
            return;
        }

        if (!TryTakeToken())
        {
            Interlocked.Increment(ref rateLimited);
            owner.CountRateLimited();
            return;
        }

        // Never waits: a full buffer (slow reader) drops the frame.
        if (channel.Writer.TryWrite(record))
        {
            Interlocked.Increment(ref buffered);
        }
        else
        {
            Interlocked.Increment(ref dropped);
            owner.CountDropped();
        }
    }

    private bool TryTakeToken()
    {
        int rate = owner.Options.MaximumEventsPerSecond;
        lock (bucketGate)
        {
            // Wall-clock ticks from the injected TimeProvider; a clock step backwards adds nothing.
            long now = clock.GetUtcNow().UtcTicks;
            tokens = Math.Min(rate, tokens + (Math.Max(0, now - refilledAt) / (double)TimeSpan.TicksPerSecond * rate));
            refilledAt = Math.Max(refilledAt, now);
            if (tokens < 1)
            {
                return false;
            }

            tokens--;
            return true;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            channel.Writer.TryComplete();
            owner.Close(this);
        }
    }
}

/// <summary>Tap counters since start. Metadata only.</summary>
public sealed record EventTapSnapshot(
    bool Enabled,
    int ActiveSessions,
    int MaximumSessions,
    long SessionsOpened,
    long SessionsRefused,
    long FramesSent,
    long FramesDropped,
    long FramesRateLimited);
