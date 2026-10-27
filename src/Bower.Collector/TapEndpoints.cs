using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Bower.Core;
using Microsoft.AspNetCore.Http.Features;

namespace Bower.Collector;

/// <summary>
/// <c>GET /v1/tap</c>: a bounded server-sent event stream of post-redaction selection
/// outcomes for <c>bower tap</c> (and, later, the console pipeline view). Requires the
/// operator credential (the shared ingest token or a BOWER_TAP_PRODUCERS producer), or a
/// loopback listener when ingest authentication is off. Every session is audited in the
/// collector log: who, filters, caps, duration and frame counts. Nothing is persisted.
/// </summary>
public static partial class CollectorApplication
{
    /// <summary>Comment written when no frame arrives for this long, so idle streams stay open and dead clients are found.</summary>
    internal static readonly TimeSpan TapKeepAlive = TimeSpan.FromSeconds(15);

    private const string SharedProducer = "default";

    private static void MapTapEndpoints(WebApplication app)
    {
        app.MapGet("/v1/tap", StreamTapAsync).AddEndpointFilter<IngestAuthenticationFilter>();
    }

    private static async Task<IResult> StreamTapAsync(
        HttpContext context,
        EventTap tap,
        CollectorSettings settings,
        IngestAuthentication authentication,
        TimeProvider clock,
        IHostApplicationLifetime lifetime,
        ILoggerFactory loggers)
    {
        ILogger logger = loggers.CreateLogger("Bower.Collector.Tap");
        string producer = context.Items[IngestAuthenticationFilter.ProducerItem] as string ?? "anonymous";
        if (!tap.Options.Enabled)
        {
            return TapError(StatusCodes.Status404NotFound, "tap-disabled");
        }

        bool authorised = authentication.Required
            ? producer == SharedProducer || settings.TapProducers.Contains(producer, StringComparer.Ordinal)
            // Without ingest authentication, only a loopback listener may tap.
            : settings.IsLoopbackListener;
        if (!authorised)
        {
            LogTapRefused(logger, producer, "tap-not-authorized");
            return TapError(StatusCodes.Status403Forbidden, "tap-not-authorized");
        }

        IQueryCollection query = context.Request.Query;
        TapPoint? point = EventTapRequest.ParsePoint(query["stage"].ToString());
        if (point is null)
        {
            // There is no parsed or raw tap point: nothing before the privacy engine is visible.
            return TapError(StatusCodes.Status400BadRequest, "tap-stage-invalid");
        }

        string? source = Blank(query["source"].ToString());
        string? eventType = Blank(query["eventType"].ToString());
        if ((source is not null && !EventTapRequest.IsValidFilter(source))
            || (eventType is not null && !EventTapRequest.IsValidFilter(eventType)))
        {
            return TapError(StatusCodes.Status400BadRequest, "tap-filter-invalid");
        }

        if (!TryPositive(query["limit"].ToString(), EventTapRequest.DefaultLimit, out int limit)
            || !TryPositive(query["durationSeconds"].ToString(), (int)EventTapRequest.DefaultDuration.TotalSeconds, out int duration)
            || !TryPositive(query["sample"].ToString(), 1, out int sample)
            || sample > EventTapRequest.MaximumSample)
        {
            return TapError(StatusCodes.Status400BadRequest, "tap-parameter-invalid");
        }

        using EventTapSession? session = tap.TryOpen(new EventTapRequest(
            producer, point.Value, source, eventType, limit, TimeSpan.FromSeconds(duration), sample));
        if (session is null)
        {
            LogTapRefused(logger, producer, "tap-session-limit");
            context.Response.Headers.RetryAfter = "5";
            return TapError(StatusCodes.Status429TooManyRequests, "tap-session-limit");
        }

        EventTapRequest effective = session.Request;
        string pointName = EventTapRequest.PointName(effective.Point);
        int durationSeconds = (int)effective.Duration.TotalSeconds;
        LogTapOpened(logger, session.Id, producer, pointName, effective.Application ?? "-",
            effective.EventType ?? "-", effective.Limit, durationSeconds, effective.Sample);

        HttpResponse response = context.Response;
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "text/event-stream; charset=utf-8";
        response.Headers.CacheControl = "no-store";
        response.Headers["X-Accel-Buffering"] = "no";
        context.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();

        CancellationToken aborted = context.RequestAborted;
        string reason = "limit";
        try
        {
            await WriteEventAsync(response, "start", JsonSerializer.SerializeToUtf8Bytes(
                new TapStartFrame(
                    EventTap.SchemaVersion, session.Id, pointName,
                    effective.Application, effective.EventType, effective.Limit,
                    durationSeconds, effective.Sample,
                    tap.Options.MaximumEventsPerSecond, tap.Options.MaximumEventBytes),
                CollectorJsonContext.Default.TapStartFrame), aborted);

            using CancellationTokenSource deadline = new(effective.Duration, clock);
            using CancellationTokenSource end = CancellationTokenSource.CreateLinkedTokenSource(
                deadline.Token, aborted, lifetime.ApplicationStopping);
            long sequence = 0;
            while (session.Sent < effective.Limit)
            {
                using CancellationTokenSource idle = new(TapKeepAlive, clock);
                using CancellationTokenSource wait = CancellationTokenSource.CreateLinkedTokenSource(end.Token, idle.Token);
                try
                {
                    if (!await session.Reader.WaitToReadAsync(wait.Token))
                    {
                        break;
                    }
                }
                catch (OperationCanceledException) when (!end.IsCancellationRequested)
                {
                    await WriteCommentAsync(response, aborted);
                    continue;
                }

                while (session.Sent < effective.Limit && session.Reader.TryRead(out EventTapRecord? record))
                {
                    await WriteEventAsync(response, "frame", Frame(record, ++sequence), aborted);
                    session.MarkSent();
                }
            }
        }
        catch (OperationCanceledException)
        {
            reason = aborted.IsCancellationRequested ? "client-closed"
                : lifetime.ApplicationStopping.IsCancellationRequested ? "shutdown"
                : "duration";
        }
        catch (IOException)
        {
            reason = "client-closed";
        }

        if (reason != "client-closed")
        {
            try
            {
                await WriteEventAsync(response, "end", JsonSerializer.SerializeToUtf8Bytes(
                    new TapEndFrame(EventTap.SchemaVersion, session.Id, reason, session.Sent, session.Dropped, session.RateLimited),
                    CollectorJsonContext.Default.TapEndFrame), aborted);
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException)
            {
                reason = "client-closed";
            }
        }

        long elapsed = (long)(clock.GetUtcNow() - session.OpenedAt).TotalMilliseconds;
        long sent = session.Sent;
        long dropped = session.Dropped;
        long rateLimited = session.RateLimited;
        LogTapClosed(logger, session.Id, reason, elapsed, sent, dropped, rateLimited);
        return Results.Empty;
    }

    /// <summary>
    /// One tap frame. Content appears only for accepted events and is the exact redacted
    /// payload that was queued; every other outcome is metadata only.
    /// </summary>
    internal static byte[] Frame(EventTapRecord record, long sequence)
    {
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", EventTap.SchemaVersion);
            writer.WriteNumber("sequence", sequence);
            writer.WriteString("observedAt", record.ObservedAt);
            writer.WriteString("stage", record.Stage);
            writer.WriteString("action", record.Action);
            writer.WriteBoolean("queued", record.Queued);
            writer.WriteBoolean("duplicate", record.Duplicate);
            writer.WriteBoolean("suppressed", record.Suppressed);
            WriteOptional(writer, "eventType", record.EventType);
            WriteOptional(writer, "application", record.Application);
            WriteOptional(writer, "environment", record.Environment);
            WriteOptional(writer, "policyId", record.PolicyId);
            writer.WriteStartArray("reasons");
            foreach (string item in record.Reasons)
            {
                writer.WriteStringValue(item);
            }

            writer.WriteEndArray();
            if (record.Event is not null)
            {
                writer.WritePropertyName("event");
                writer.WriteRawValue(record.Event);
            }
            else
            {
                writer.WriteString("eventOmitted", record.EventOmitted);
            }

            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(name);
        }
        else
        {
            writer.WriteString(name, value);
        }
    }

    private static async Task WriteEventAsync(HttpResponse response, string name, byte[] json, CancellationToken cancellationToken)
    {
        // Compact JSON never contains a raw line break, so one data line carries the frame.
        await response.Body.WriteAsync(Encoding.UTF8.GetBytes($"event: {name}\ndata: "), cancellationToken);
        await response.Body.WriteAsync(json, cancellationToken);
        await response.Body.WriteAsync("\n\n"u8.ToArray(), cancellationToken);
        await response.Body.FlushAsync(cancellationToken);
    }

    private static async Task WriteCommentAsync(HttpResponse response, CancellationToken cancellationToken)
    {
        await response.Body.WriteAsync(": keep-alive\n\n"u8.ToArray(), cancellationToken);
        await response.Body.FlushAsync(cancellationToken);
    }

    private static bool TryPositive(string value, int fallback, out int result)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            result = fallback;
            return true;
        }

        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result) && result > 0;
    }

    private static string? Blank(string value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static IResult TapError(int status, string error) =>
        Results.Json(new ErrorResponse(error), CollectorJsonContext.Default.ErrorResponse, statusCode: status);

    [LoggerMessage(EventId = 1200, Level = LogLevel.Information,
        Message = "Tap session {SessionId} opened by producer {Producer}: tap point {TapPoint}, source {Source}, " +
            "event type {EventType}, limit {Limit}, duration {DurationSeconds} s, sample 1 in {Sample}.")]
    private static partial void LogTapOpened(ILogger logger, string sessionId, string producer, string tapPoint,
        string source, string eventType, int limit, int durationSeconds, int sample);

    [LoggerMessage(EventId = 1201, Level = LogLevel.Information,
        Message = "Tap session {SessionId} closed ({Reason}) after {ElapsedMilliseconds} ms: {Sent} frames sent, " +
            "{Dropped} dropped, {RateLimited} rate limited.")]
    private static partial void LogTapClosed(ILogger logger, string sessionId, string reason, long elapsedMilliseconds,
        long sent, long dropped, long rateLimited);

    [LoggerMessage(EventId = 1202, Level = LogLevel.Warning, Message = "Tap session refused for producer {Producer}: {Reason}.")]
    private static partial void LogTapRefused(ILogger logger, string producer, string reason);
}
