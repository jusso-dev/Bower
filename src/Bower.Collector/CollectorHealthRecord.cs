using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;

namespace Bower.Collector;

/// <summary>What one collector health record reports. Metadata only: counts, states and times.</summary>
public sealed record CollectorHealthSample(
    DateTimeOffset At,
    DateTimeOffset CollectorStartedAt,
    long Sequence,
    TimeSpan Interval,
    string OutputType,
    string DeliveryStatus,
    DateTimeOffset? LastSuccessfulDeliveryAt,
    QueueSnapshot Queue,
    long QueueCapacityBytes,
    IntakeMetricsSnapshot Intake,
    PipelineMetricsSnapshot Pipeline,
    bool SourcesConfigured,
    IReadOnlyList<SourceSilenceStatus> Sources,
    IReadOnlyList<SyslogListenerStatus>? Syslog,
    IReadOnlyList<WindowsEventSubscriptionStatus>? WindowsEventLog,
    long? QueueFileBytes = null,
    long? QueueFileLimitBytes = null);

/// <summary>
/// Builds the periodic <c>collector_health</c> record. It travels through the same redaction,
/// policy and queue as any event, so its arrival in Sentinel proves the whole delivery path,
/// and its absence is the destination-side signal for a stopped collector or failed delivery.
/// Never carries payloads, event ids, credentials, endpoints or free-form error text.
/// <para>
/// Every number stays below <see cref="MaximumReportedValue"/>: default privacy detectors scan
/// JSON numbers, and an eight-digit or longer value can match a card, TFN, ABN or Medicare
/// checksum and be masked, which would break numeric alert comparisons. So counters are
/// deltas since the previous record (<c>countersSince</c>), sizes are MiB and ages are clamped.
/// Lifetime totals stay in the token-protected <c>/v1/status</c>.
/// </para>
/// </summary>
public static class CollectorHealthRecord
{
    public const string RecordVersion = "1";
    public const string EventAction = "collector.health";
    public const string SourceAdapter = "collector-health";
    public const string ApplicationName = "bower-collector";

    /// <summary>Most overdue sources, syslog listeners and Windows subscriptions listed per record.</summary>
    public const int MaximumListed = 25;

    /// <summary>Largest number written (seven digits). Larger values are clamped to it.</summary>
    public const long MaximumReportedValue = 9_999_999;

    /// <summary>Bounded problem codes, in this order, so queries need no thresholds of their own.</summary>
    public const string DeadLetters = "dead-letters";
    public const string Backpressure = "backpressure";
    public const string Stalled = "stalled";
    public const string Retrying = "retrying";
    public const string CapacityRefusals = "capacity-refusals";
    public const string SourceOverdue = "source-overdue";
    public const string SyslogErrors = "syslog-errors";
    public const string WindowsEventLogErrors = "windows-event-log-errors";

    public static string CreateJson(
        CollectorHealthSample sample,
        string collectorId,
        string environment,
        CollectorHealthSample? previous = null) =>
        JsonSerializer.Serialize(Create(sample, collectorId, environment, previous), BowerJson.Envelope);

    /// <summary>
    /// The record for <paramref name="sample"/>. Counters are reported as the change since
    /// <paramref name="previous"/>, the last sample of this process that was queued; without
    /// one (or after a restart) they count from process start.
    /// </summary>
    public static SecurityEventEnvelope Create(
        CollectorHealthSample sample,
        string collectorId,
        string environment,
        CollectorHealthSample? previous = null)
    {
        ArgumentNullException.ThrowIfNull(sample);
        ArgumentException.ThrowIfNullOrWhiteSpace(collectorId);
        CollectorHealthSample? baseline = Baseline(sample, previous);
        IReadOnlyList<string> problems = Problems(sample, baseline);
        // Unique per process start and sequence: a restart starts a new series and never
        // collides with (or is mistaken for a conflicting copy of) an earlier record.
        string eventId = "collector-health-" + LetterHash(
            "bower-collector-health-v1",
            collectorId,
            Time(sample.CollectorStartedAt),
            sample.Sequence.ToString(CultureInfo.InvariantCulture))[..32];
        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            EventOriginalId = eventId,
            TimeGenerated = sample.At,
            TimeObserved = sample.At,
            EventCategory = SecurityEventCategories.CollectorHealth,
            EventType = SecurityEventTypes.CollectorHealth,
            EventAction = EventAction,
            EventResult = problems.Count == 0 ? EventResult.Success : EventResult.Failure,
            EventSeverity = problems.Count == 0 ? EventSeverity.Informational : EventSeverity.Medium,
            EventOutcomeReason = problems.Count == 0
                ? "Collector health: healthy"
                : "Collector health: " + string.Join(", ", problems),
            Application = new ApplicationContext { Name = ApplicationName, Environment = environment },
            Actor = new ActorContext { Username = "bower.health", Type = ActorType.System },
            Request = new RequestContext { CorrelationId = eventId },
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["healthRecordVersion"] = RecordVersion
            },
            Attributes = Attributes(sample, baseline, problems)
        };
    }

    /// <summary>Problem codes for <paramref name="sample"/>; counters compare with <paramref name="previous"/>.</summary>
    public static IReadOnlyList<string> Problems(CollectorHealthSample sample, CollectorHealthSample? previous)
    {
        ArgumentNullException.ThrowIfNull(sample);
        CollectorHealthSample? baseline = Baseline(sample, previous);
        List<string> problems = [];
        if (sample.Queue.DeadLettered > 0) problems.Add(DeadLetters);
        if (sample.DeliveryStatus == "backpressure") problems.Add(Backpressure);
        if (sample.DeliveryStatus == "stalled") problems.Add(Stalled);
        if (sample.DeliveryStatus == "retrying") problems.Add(Retrying);
        if (Delta(sample.Intake.CapacityRefusals, baseline?.Intake.CapacityRefusals)
            + Delta(sample.Intake.PrivacyAlertRefusals, baseline?.Intake.PrivacyAlertRefusals) > 0)
        {
            problems.Add(CapacityRefusals);
        }

        if (sample.Sources.Any(source => source.IsOverdue)) problems.Add(SourceOverdue);
        if ((sample.Syslog ?? []).Any(item => SyslogErrorCount(item, Match(baseline?.Syslog, item.Id)) > 0))
        {
            problems.Add(SyslogErrors);
        }

        if ((sample.WindowsEventLog ?? []).Any(item =>
                !HealthyWindowsState(item.State) || WindowsErrorCount(item, Match(baseline?.WindowsEventLog, item.Id)) > 0))
        {
            problems.Add(WindowsEventLogErrors);
        }

        return problems;
    }

    // Counters reset on restart; only a sample of the same process is a baseline.
    private static CollectorHealthSample? Baseline(CollectorHealthSample sample, CollectorHealthSample? previous) =>
        previous is not null && previous.CollectorStartedAt == sample.CollectorStartedAt && previous.At <= sample.At
            ? previous
            : null;

    // Counters that mean frames or connections were refused or lost before durable acceptance.
    private static long SyslogErrorCount(SyslogListenerStatus item, SyslogListenerStatus? before) =>
        Delta(item.ConnectionsRejected, before?.ConnectionsRejected) + Delta(item.SendersDenied, before?.SendersDenied)
        + Delta(item.TlsHandshakeFailures, before?.TlsHandshakeFailures) + Delta(item.Malformed, before?.Malformed)
        + Delta(item.Oversized, before?.Oversized) + Delta(item.FramingErrors, before?.FramingErrors)
        + Delta(item.Timeouts, before?.Timeouts) + Delta(item.Dropped, before?.Dropped)
        + Delta(item.SubmitFailures, before?.SubmitFailures) + Delta(item.ReceiveErrors, before?.ReceiveErrors)
        + Delta(item.ParserErrors, before?.ParserErrors);

    private static long WindowsErrorCount(WindowsEventSubscriptionStatus item, WindowsEventSubscriptionStatus? before) =>
        Delta(item.ReadErrors, before?.ReadErrors) + Delta(item.Gaps, before?.Gaps) + Delta(item.Resets, before?.Resets)
        + Delta(item.SubmitFailures, before?.SubmitFailures) + Delta(item.ParserErrors, before?.ParserErrors)
        + Delta(item.Malformed, before?.Malformed) + Delta(item.Oversized, before?.Oversized)
        + Delta(item.CursorConflicts, before?.CursorConflicts);

    private static bool HealthyWindowsState(string state) => state is "starting" or "running" or "backpressure";

    private static SyslogListenerStatus? Match(IReadOnlyList<SyslogListenerStatus>? listeners, string id) =>
        listeners?.FirstOrDefault(item => item.Id == id);

    private static WindowsEventSubscriptionStatus? Match(IReadOnlyList<WindowsEventSubscriptionStatus>? subscriptions, string id) =>
        subscriptions?.FirstOrDefault(item => item.Id == id);

    private static long Delta(long current, long? before) => Math.Max(0, current - (before ?? 0));

    private static Dictionary<string, JsonElement> Attributes(
        CollectorHealthSample sample,
        CollectorHealthSample? baseline,
        IReadOnlyList<string> problems)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("recordVersion", RecordVersion);
            Number(writer, "intervalSeconds", (long)sample.Interval.TotalSeconds);
            Number(writer, "sequence", sample.Sequence);
            writer.WriteString("collectorStartedAt", Time(sample.CollectorStartedAt));
            writer.WriteString("countersSince", Time(baseline?.At ?? sample.CollectorStartedAt));
            writer.WriteString("status", problems.Count == 0 ? "healthy" : "degraded");
            writer.WriteStartArray("problems");
            foreach (string problem in problems)
            {
                writer.WriteStringValue(problem);
            }

            writer.WriteEndArray();

            writer.WriteStartObject("delivery");
            writer.WriteString("output", sample.OutputType);
            writer.WriteString("status", sample.DeliveryStatus);
            WriteTime(writer, "lastSuccessfulDeliveryAt", sample.LastSuccessfulDeliveryAt);
            writer.WriteEndObject();

            QueueSnapshot queue = sample.Queue;
            writer.WriteStartObject("queue");
            Number(writer, "queued", queue.Queued);
            Number(writer, "retrying", queue.Retrying);
            Number(writer, "uploading", queue.Uploading);
            Number(writer, "undelivered", queue.Queued + queue.Retrying + queue.Uploading);
            Number(writer, "deadLettered", queue.DeadLettered);
            WriteTime(writer, "oldestUndeliveredAt", queue.OldestUndelivered);
            if (queue.OldestUndelivered is { } oldest)
            {
                Number(writer, "oldestUndeliveredAgeSeconds", (long)(sample.At - oldest).TotalSeconds);
            }
            else
            {
                writer.WriteNull("oldestUndeliveredAgeSeconds");
            }

            writer.WriteEndObject();

            // EXTENSION POINT (storage): only what the queue reports today. Free disk and
            // watermark fields for the queue, spool and archive volumes join this object
            // additively (MiB or percent, never raw bytes); alert queries read them with a
            // null-tolerant coalesce.
            writer.WriteStartObject("storage");
            Mebibytes(writer, "queueCapacityMiB", sample.QueueCapacityBytes);
            Mebibytes(writer, "undeliveredMiB", queue.UndeliveredBytes);
            Mebibytes(writer, "storedMiB", queue.TotalBytes);
            writer.WriteNumber("capacityUsedPercent", Percent(queue.UndeliveredBytes, sample.QueueCapacityBytes));
            // The database file stops growing at its page limit (SQLite "database or disk is
            // full") before undelivered payloads reach BOWER_QUEUE_MAX_BYTES: rows, indexes,
            // the ledger and retained acknowledged rows all use pages.
            if (sample.QueueFileBytes is { } fileBytes && sample.QueueFileLimitBytes is { } limitBytes)
            {
                Mebibytes(writer, "queueFileMiB", fileBytes);
                Mebibytes(writer, "queueFileLimitMiB", limitBytes);
                writer.WriteNumber("queueFileUsedPercent", Percent(fileBytes, limitBytes));
            }

            writer.WriteEndObject();

            IntakeMetricsSnapshot intake = sample.Intake;
            IntakeMetricsSnapshot? intakeBefore = baseline?.Intake;
            writer.WriteStartObject("intake");
            Number(writer, "attemptedRequests", Delta(intake.AttemptedRequests, intakeBefore?.AttemptedRequests));
            Number(writer, "capacityRefusals", Delta(intake.CapacityRefusals, intakeBefore?.CapacityRefusals));
            Number(writer, "privacyAlertRefusals", Delta(intake.PrivacyAlertRefusals, intakeBefore?.PrivacyAlertRefusals));
            WriteTime(writer, "lastRefusalAt", intake.LastRefusalAt);
            if (intake.LastRefusalReason is { } reason)
            {
                writer.WriteString("lastRefusalReason", reason);
            }
            else
            {
                writer.WriteNull("lastRefusalReason");
            }

            writer.WriteEndObject();

            PipelineMetricsSnapshot pipeline = sample.Pipeline;
            PipelineMetricsSnapshot? pipelineBefore = baseline?.Pipeline;
            writer.WriteStartObject("pipeline");
            Number(writer, "eventsIn", Delta(pipeline.EventsIn, pipelineBefore?.EventsIn));
            Number(writer, "eventsQueued", Delta(pipeline.EventsQueued, pipelineBefore?.EventsQueued));
            Number(writer, "duplicates", Delta(pipeline.Duplicates, pipelineBefore?.Duplicates));
            Number(writer, "suppressed", Delta(pipeline.Suppressed, pipelineBefore?.Suppressed));
            writer.WriteEndObject();

            WriteSources(writer, sample);
            WriteSyslog(writer, sample.Syslog, baseline?.Syslog);
            WriteWindowsEventLog(writer, sample.WindowsEventLog, baseline?.WindowsEventLog);
            writer.WriteEndObject();
        }

        using JsonDocument document = JsonDocument.Parse(stream.ToArray());
        Dictionary<string, JsonElement> attributes = new(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            attributes[property.Name] = property.Value.Clone();
        }

        return attributes;
    }

    private static void WriteSources(Utf8JsonWriter writer, CollectorHealthSample sample)
    {
        IReadOnlyList<SourceSilenceStatus> sources = sample.Sources;
        writer.WriteStartObject("sources");
        writer.WriteBoolean("configured", sample.SourcesConfigured);
        Number(writer, "expected", sources.Count);
        Number(writer, "active", sources.Count(item => item.State == "active"));
        Number(writer, "pending", sources.Count(item => item.State == "pending"));
        Number(writer, "silent", sources.Count(item => item.State == "silent"));
        Number(writer, "neverSeen", sources.Count(item => item.State == "never-seen"));
        writer.WriteStartArray("overdue");
        foreach (SourceSilenceStatus source in sources.Where(item => item.IsOverdue)
            .OrderByDescending(item => item.SilentSeconds)
            .ThenBy(item => item.Application, StringComparer.Ordinal)
            .ThenBy(item => item.Environment, StringComparer.Ordinal)
            .Take(MaximumListed))
        {
            writer.WriteStartObject();
            writer.WriteString("application", source.Application);
            writer.WriteString("environment", source.Environment);
            writer.WriteString("state", source.State);
            Number(writer, "silentSeconds", source.SilentSeconds);
            Number(writer, "allowedSilenceSeconds", source.AllowedSilenceSeconds);
            WriteTime(writer, "lastSeenAt", source.LastSeenAt);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteSyslog(
        Utf8JsonWriter writer,
        IReadOnlyList<SyslogListenerStatus>? listeners,
        IReadOnlyList<SyslogListenerStatus>? baseline)
    {
        writer.WriteStartArray("syslog");
        foreach (SyslogListenerStatus item in (listeners ?? []).Take(MaximumListed))
        {
            // The endpoint is configuration, not health; it stays in the token-protected status.
            SyslogListenerStatus? before = Match(baseline, item.Id);
            writer.WriteStartObject();
            writer.WriteString("id", item.Id);
            writer.WriteString("protocol", item.Protocol);
            Number(writer, "activeConnections", item.ActiveConnections);
            Number(writer, "connectionsAccepted", Delta(item.ConnectionsAccepted, before?.ConnectionsAccepted));
            Number(writer, "connectionsRejected", Delta(item.ConnectionsRejected, before?.ConnectionsRejected));
            Number(writer, "sendersDenied", Delta(item.SendersDenied, before?.SendersDenied));
            Number(writer, "tlsHandshakeFailures", Delta(item.TlsHandshakeFailures, before?.TlsHandshakeFailures));
            Number(writer, "framesReceived", Delta(item.FramesReceived, before?.FramesReceived));
            Number(writer, "queued", Delta(item.Queued, before?.Queued));
            Number(writer, "notRouted", Delta(item.NotRouted, before?.NotRouted));
            Number(writer, "parserErrors", Delta(item.ParserErrors, before?.ParserErrors));
            Number(writer, "malformed", Delta(item.Malformed, before?.Malformed));
            Number(writer, "oversized", Delta(item.Oversized, before?.Oversized));
            Number(writer, "framingErrors", Delta(item.FramingErrors, before?.FramingErrors));
            Number(writer, "timeouts", Delta(item.Timeouts, before?.Timeouts));
            Number(writer, "dropped", Delta(item.Dropped, before?.Dropped));
            Number(writer, "retries", Delta(item.Retries, before?.Retries));
            Number(writer, "submitFailures", Delta(item.SubmitFailures, before?.SubmitFailures));
            Number(writer, "receiveErrors", Delta(item.ReceiveErrors, before?.ReceiveErrors));
            WriteTime(writer, "lastFrameAt", item.LastFrameAt);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static void WriteWindowsEventLog(
        Utf8JsonWriter writer,
        IReadOnlyList<WindowsEventSubscriptionStatus>? subscriptions,
        IReadOnlyList<WindowsEventSubscriptionStatus>? baseline)
    {
        writer.WriteStartArray("windowsEventLog");
        foreach (WindowsEventSubscriptionStatus item in (subscriptions ?? []).Take(MaximumListed))
        {
            WindowsEventSubscriptionStatus? before = Match(baseline, item.Id);
            writer.WriteStartObject();
            writer.WriteString("id", item.Id);
            writer.WriteString("channel", item.Channel);
            writer.WriteString("state", item.State);
            Number(writer, "eventsRead", Delta(item.EventsRead, before?.EventsRead));
            Number(writer, "queued", Delta(item.Queued, before?.Queued));
            Number(writer, "notSelected", Delta(item.NotSelected, before?.NotSelected));
            Number(writer, "parserErrors", Delta(item.ParserErrors, before?.ParserErrors));
            Number(writer, "readErrors", Delta(item.ReadErrors, before?.ReadErrors));
            Number(writer, "gaps", Delta(item.Gaps, before?.Gaps));
            Number(writer, "resets", Delta(item.Resets, before?.Resets));
            Number(writer, "retries", Delta(item.Retries, before?.Retries));
            Number(writer, "submitFailures", Delta(item.SubmitFailures, before?.SubmitFailures));
            Number(writer, "cursorConflicts", Delta(item.CursorConflicts, before?.CursorConflicts));
            WriteTime(writer, "lastEventAt", item.LastEventAt);
            WriteTime(writer, "lastPollAt", item.LastPollAt);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static double Percent(long used, long limit) =>
        limit <= 0 ? 0 : Math.Min(100.0, Math.Round(100.0 * Math.Max(0, used) / limit, 1));

    private static void Number(Utf8JsonWriter writer, string name, long value) =>
        writer.WriteNumber(name, Math.Clamp(value, 0, MaximumReportedValue));

    // One decimal, so the integer part stays within seven digits up to about 9.5 TiB.
    private static void Mebibytes(Utf8JsonWriter writer, string name, long bytes) =>
        writer.WriteNumber(name, Math.Min(MaximumReportedValue, Math.Round(Math.Max(0, bytes) / 1_048_576.0, 1)));

    private static string Time(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static void WriteTime(Utf8JsonWriter writer, string name, DateTimeOffset? value)
    {
        if (value is { } time)
        {
            writer.WriteString(name, Time(time));
        }
        else
        {
            writer.WriteNull(name);
        }
    }

    /// <summary>
    /// Length-framed SHA-256 (as <c>EventIdentity</c>) written with the letters a-p instead of
    /// hex digits: a run of digits in an id can match a numeric privacy detector and be masked.
    /// </summary>
    private static string LetterHash(params string[] parts)
    {
        string material = string.Concat(parts.Select(part =>
            Encoding.UTF8.GetByteCount(part).ToString(CultureInfo.InvariantCulture) + ":" + part));
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return string.Create(hash.Length * 2, hash, static (letters, bytes) =>
        {
            for (int index = 0; index < bytes.Length; index++)
            {
                letters[index * 2] = (char)('a' + (bytes[index] >> 4));
                letters[(index * 2) + 1] = (char)('a' + (bytes[index] & 0xF));
            }
        });
    }
}
