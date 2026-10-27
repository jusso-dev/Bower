using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Bower.Cli.Commands;

/// <summary>
/// Renders <c>bower top</c> from two <c>/v1/status</c> documents. Pure and deterministic so
/// the C# and Rust CLIs print identical text (shared fixtures under
/// <c>rust/crates/bower-cli/tests/fixtures/top</c>). Rates use integer tenths, never floats.
/// Every number comes from status counters; nothing here is event content.
/// </summary>
internal static class TopView
{
    private static readonly string[] StageOrder = ["transform", "redaction", "schema", "validation", "policy"];

    public static string Render(
        string collector,
        JsonElement? previous,
        JsonElement current,
        long elapsedMilliseconds,
        DateTimeOffset now)
    {
        StringBuilder text = new();
        string Rate(long value, long before) => RateText(value, before, previous is not null, elapsedMilliseconds);
        string interval = previous is null ? "-" : $"{Decimal((elapsedMilliseconds + 50) / 100)} s";
        Line(text, $"bower top  {collector}  status {Text(current, "status")}  interval {interval}");
        text.Append('\n');

        JsonElement intake = Property(current, "intake");
        long attempts = Number(intake, "attemptedRequests");
        Line(text, $"Intake  attempts {attempts} ({Rate(attempts, Number(Property(previous, "intake"), "attemptedRequests"))}/s)"
            + $"  capacity refusals {Number(intake, "capacityRefusals")}"
            + $"  privacy alert refusals {Number(intake, "privacyAlertRefusals")}");
        text.Append('\n');

        // Per stage, from the selection counters. The total row equals pipeline.eventsIn.
        JsonElement[] rows = Array(Property(current, "pipeline"), "rows");
        JsonElement[] previousRows = Array(Property(previous, "pipeline"), "rows");
        Line(text, Row(L("STAGE", 11), R("EVENTS", 9), R("/S", 7), R("ACCEPTED", 9), R("REJECTED", 9),
            R("QUARANTINED", 11), R("OTHER", 7), R("SUPPRESSED", 10), R("QUEUED", 9), R("DUPLICATES", 10)));
        foreach (string stage in StageOrder)
        {
            JsonElement[] stageRows = [.. rows.Where(row => Text(row, "stage") == stage)];
            if (stageRows.Length > 0)
            {
                long before = Sum([.. previousRows.Where(row => Text(row, "stage") == stage)], "events");
                Line(text, StageRow(stage, stageRows, Sum(stageRows, "events"), Rate(Sum(stageRows, "events"), before)));
            }
        }

        long total = Number(Property(current, "pipeline"), "eventsIn");
        Line(text, StageRow("total", rows, total, Rate(total, Number(Property(previous, "pipeline"), "eventsIn"))));
        text.Append('\n');

        Line(text, Row(L("STAGE", 11), L("POLICY", 32), L("ACTION", 18), R("EVENTS", 9), R("/S", 7)));
        foreach (JsonElement row in rows)
        {
            long events = Number(row, "events");
            long before = previousRows
                .Where(item => Text(item, "stage") == Text(row, "stage")
                    && Text(item, "policyId") == Text(row, "policyId")
                    && Text(item, "action") == Text(row, "action"))
                .Sum(item => Number(item, "events"));
            Line(text, Row(L(Text(row, "stage"), 11), L(Text(row, "policyId"), 32), L(Text(row, "action"), 18),
                R(events, 9), R(Rate(events, before), 7)));
        }

        text.Append('\n');
        Line(text, Row(L("SOURCE", 32), L("ENVIRONMENT", 18), R("EVENTS", 9), R("/S", 7)));
        JsonElement[] previousSources = Array(previous, "activity");
        foreach (JsonElement source in Array(current, "activity"))
        {
            long events = Number(source, "eventCount");
            long before = previousSources
                .Where(item => Text(item, "application") == Text(source, "application")
                    && Text(item, "environment") == Text(source, "environment"))
                .Sum(item => Number(item, "eventCount"));
            Line(text, Row(L(Text(source, "application"), 32), L(Text(source, "environment"), 18),
                R(events, 9), R(Rate(events, before), 7)));
        }

        JsonElement[] listeners = Array(current, "syslog");
        if (listeners.Length > 0)
        {
            text.Append('\n');
            Line(text, Row(L("SYSLOG", 18), L("PROTOCOL", 8), R("FRAMES", 9), R("/S", 7), R("QUEUED", 9),
                R("REJECTED", 9), R("DROPPED", 8), R("MALFORMED", 9), R("OVERSIZED", 9), R("DENIED", 7),
                R("RECV ERRORS", 11), R("CONNS", 6)));
            JsonElement[] previousListeners = Array(previous, "syslog");
            foreach (JsonElement listener in listeners)
            {
                long frames = Number(listener, "framesReceived");
                long before = previousListeners
                    .Where(item => Text(item, "id") == Text(listener, "id"))
                    .Sum(item => Number(item, "framesReceived"));
                Line(text, Row(L(Text(listener, "id"), 18), L(Text(listener, "protocol"), 8), R(frames, 9),
                    R(Rate(frames, before), 7), R(Number(listener, "queued"), 9), R(Number(listener, "rejected"), 9),
                    R(Number(listener, "dropped"), 8), R(Number(listener, "malformed"), 9),
                    R(Number(listener, "oversized"), 9), R(Number(listener, "sendersDenied"), 7),
                    R(Number(listener, "receiveErrors"), 11), R(Number(listener, "activeConnections"), 6)));
            }
        }

        text.Append('\n');
        JsonElement queue = Property(current, "queue");
        string oldest = Property(queue, "oldestUndelivered") is { ValueKind: JsonValueKind.String } value
            && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset at)
            ? $"{Math.Max(0, (long)Math.Floor((now - at).TotalSeconds))} s"
            : "-";
        Line(text, $"Queue     queued {Number(queue, "queued")}  retrying {Number(queue, "retrying")}"
            + $"  uploading {Number(queue, "uploading")}  dead letters {Number(queue, "deadLettered")}"
            + $"  undelivered bytes {Number(queue, "undeliveredBytes")}  oldest undelivered {oldest}");

        JsonElement delivery = Property(current, "delivery");
        string latency = Property(delivery, "latencyEwmaMilliseconds") is { ValueKind: JsonValueKind.Number } ewma
            ? $"{ewma.GetInt64()} ms"
            : "-";
        Line(text, delivery.ValueKind == JsonValueKind.Object
            ? $"Delivery  output {Text(delivery, "outputId")}  limit {Number(delivery, "limit")}"
                + $" ({Number(delivery, "minimumLimit")}-{Number(delivery, "maximumLimit")})"
                + $"  in flight {Number(delivery, "inFlight")}  latency {latency}"
                + $"  throttles {Number(delivery, "throttles")}  server errors {Number(delivery, "serverErrors")}"
                + $"  timeouts {Number(delivery, "timeouts")}"
            : "Delivery  -");

        JsonElement tap = Property(current, "tap");
        Line(text, tap.ValueKind == JsonValueKind.Object
            ? $"Tap       {(Property(tap, "enabled").ValueKind == JsonValueKind.True ? "enabled" : "disabled")}"
                + $"  sessions {Number(tap, "activeSessions")}/{Number(tap, "maximumSessions")}"
                + $"  opened {Number(tap, "sessionsOpened")}  refused {Number(tap, "sessionsRefused")}"
                + $"  frames sent {Number(tap, "framesSent")}  dropped {Number(tap, "framesDropped")}"
                + $"  rate limited {Number(tap, "framesRateLimited")}"
            : "Tap       -");
        return text.ToString();
    }

    private static string StageRow(string stage, JsonElement[] rows, long events, string rate)
    {
        long Count(params string[] actions) =>
            rows.Where(row => actions.Contains(Text(row, "action"))).Sum(row => Number(row, "events"));
        long accepted = Count("accept", "redact-and-accept");
        long rejected = Count("reject");
        long quarantined = Count("quarantine");
        return Row(L(stage, 11), R(events, 9), R(rate, 7), R(accepted, 9), R(rejected, 9), R(quarantined, 11),
            R(events - accepted - rejected - quarantined, 7), R(Sum(rows, "suppressed"), 10),
            R(Sum(rows, "queued"), 9), R(Sum(rows, "duplicates"), 10));
    }

    /// <summary>Per-second rate in tenths; "-" without a previous sample or after a counter reset.</summary>
    internal static string RateText(long current, long previous, bool hasPrevious, long elapsedMilliseconds) =>
        !hasPrevious || elapsedMilliseconds <= 0 || current < previous
            ? "-"
            : Decimal((((current - previous) * 10_000) + (elapsedMilliseconds / 2)) / elapsedMilliseconds);

    private static string Decimal(long tenths) =>
        string.Create(CultureInfo.InvariantCulture, $"{tenths / 10}.{tenths % 10}");

    private readonly record struct Cell(string Text, int Width, bool AlignRight);

    private static Cell L(string text, int width) => new(text, width, false);

    private static Cell R(string text, int width) => new(text, width, true);

    private static Cell R(long value, int width) => new(value.ToString(CultureInfo.InvariantCulture), width, true);

    /// <summary>Cells padded to their width (left or right aligned), one space apart, trailing spaces trimmed.</summary>
    private static string Row(params Cell[] cells) =>
        string.Join(' ', cells.Select(cell => cell.AlignRight ? cell.Text.PadLeft(cell.Width) : cell.Text.PadRight(cell.Width)))
            .TrimEnd();

    private static void Line(StringBuilder text, string line) => text.Append(line).Append('\n');

    private static JsonElement Property(JsonElement? element, string name) =>
        element is { ValueKind: JsonValueKind.Object } value && value.TryGetProperty(name, out JsonElement property)
            ? property
            : default;

    private static string Text(JsonElement element, string name) =>
        Property(element, name) is { ValueKind: JsonValueKind.String } value ? value.GetString()! : "-";

    private static long Number(JsonElement element, string name) =>
        Property(element, name) is { ValueKind: JsonValueKind.Number } value && value.TryGetInt64(out long number)
            ? number
            : 0;

    private static long Sum(JsonElement[] rows, string name) => rows.Sum(row => Number(row, name));

    private static JsonElement[] Array(JsonElement? element, string name) => Array(Property(element, name));

    private static JsonElement[] Array(JsonElement element) =>
        element.ValueKind == JsonValueKind.Array ? [.. element.EnumerateArray()] : [];
}
