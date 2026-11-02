using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Core;
using Bower.Persistence;

namespace Bower.Cli.Commands;

internal static class ArchiveCommands
{
    /// <summary>bower archive create --archive DIR [--database FILE] [--collector-id ID]</summary>
    public static async Task<int> CreateAsync(string[] args)
    {
        SqliteEventStore store = await QueueCommands.OpenStoreAsync(args);
        QueueArchive archive = new(
            CliOptions.Required(args, "--archive"),
            CliOptions.Get(args, "--collector-id") ?? Environment.MachineName);
        ArchiveRunResult result = await archive.ArchiveAsync(store);
        Console.WriteLine(JsonSerializer.Serialize(
            new ArchiveCreateOutput(result.Segments, result.Events, result.HeadSequence, result.HeadHash),
            CliJsonContext.Default.ArchiveCreateOutput));
        return 0;
    }

    /// <summary>bower archive verify --archive DIR [--anchor SEQUENCE:HASH]</summary>
    public static async Task<int> VerifyAsync(string[] args)
    {
        QueueArchive archive = new(CliOptions.Required(args, "--archive"), "verifier");
        ArchiveVerification result = await archive.VerifyAsync(ParseAnchor(CliOptions.Get(args, "--anchor")));
        Console.WriteLine(JsonSerializer.Serialize(ArchiveVerifyOutput.From(result), CliJsonContext.Default.ArchiveVerifyOutput));
        return result.Intact ? 0 : 3;
    }

    /// <summary>
    /// bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
    ///   [--event-type TYPE]... [--collector-id ID] [--dry-run]
    /// Verifies the archive, then posts selected events through a collector's full intake
    /// labelled <c>bowerReplay: archive</c> and <c>bowerReplayCollectorId</c>, always the
    /// archived envelope's stamped <c>collector.id</c> (a label the producer set is replaced).
    /// Sends BOWER_INGEST_TOKEN when set. Use a replay collector with its own queue (the
    /// original queue reports replayed events as duplicates) and the original
    /// BOWER_COLLECTOR_ID: Sentinel identifies events by (CollectorId, EventId). A collector
    /// with another id refuses an event; it is counted as <c>collector-mismatch</c>, the replay
    /// continues, and the exit code is 2. <c>--collector-id</c> selects one collector's events,
    /// so an archive spanning an id change is replayed one slice per matching collector.
    /// </summary>
    public static Task<int> ReplayAsync(string[] args) => ReplayAsync(args, null, Console.Out, Console.Error);

    internal static async Task<int> ReplayAsync(string[] args, HttpMessageHandler? handler, TextWriter output, TextWriter error)
    {
        QueueArchive archive = new(CliOptions.Required(args, "--archive"), "replay");
        ArchiveVerification verification = await archive.VerifyAsync();
        if (!verification.Intact)
        {
            output.WriteLine(JsonSerializer.Serialize(ArchiveVerifyOutput.From(verification), CliJsonContext.Default.ArchiveVerifyOutput));
            error.WriteLine("Archive failed verification; replay refused.");
            return 3;
        }

        DateTimeOffset? from = CliOptions.Timestamp(CliOptions.Get(args, "--from"), "--from");
        DateTimeOffset? to = CliOptions.Timestamp(CliOptions.Get(args, "--to"), "--to");
        HashSet<string> eventTypes = CliOptions.All(args, "--event-type").ToHashSet(StringComparer.Ordinal);
        string? collectorId = CliOptions.Get(args, "--collector-id");
        bool dryRun = CliOptions.Has(args, "--dry-run");
        string collector = CliOptions.Required(args, "--collector-url");
        using HttpClient client = new(handler ?? new HttpClientHandler(), disposeHandler: true)
        {
            BaseAddress = new Uri(collector.EndsWith('/') ? collector : collector + "/"),
            Timeout = TimeSpan.FromSeconds(30)
        };
        if (Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN") is { Length: > 0 } token)
        {
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        }

        SortedDictionary<string, long> responses = new(StringComparer.Ordinal);
        long selected = 0;
        await foreach (ArchivedEvent item in archive.ReadAllAsync())
        {
            JsonObject envelope = JsonNode.Parse(item.Payload)?.AsObject()
                ?? throw new InvalidDataException($"Archived event {item.Sequence} is not a JSON object.");
            DateTimeOffset generated = DateTimeOffset.Parse(
                envelope["timeGenerated"]?.GetValue<string>() ?? string.Empty,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
            string eventType = envelope["eventType"]?.GetValue<string>() ?? string.Empty;
            string? origin = (envelope["collector"] as JsonObject)?["id"] is JsonValue stamped
                && stamped.TryGetValue(out string? stampedId) && stampedId.Length > 0 ? stampedId : null;
            if ((from is not null && generated < from)
                || (to is not null && generated >= to)
                || (eventTypes.Count > 0 && !eventTypes.Contains(eventType))
                || (collectorId is not null && !string.Equals(origin, collectorId, StringComparison.Ordinal)))
            {
                continue;
            }

            selected++;
            if (dryRun)
            {
                continue;
            }

            JsonObject labels = envelope["labels"] as JsonObject ?? [];
            labels["bowerReplay"] = "archive";
            // The receiving collector stamps its own id and refuses the replay unless it
            // equals the stamped origin, so the replay keeps the original (CollectorId,
            // EventId). Only the collector-stamped value counts: any label a producer set is
            // replaced, or removed when the envelope has no stamped collector.
            labels.Remove("bowerReplayCollectorId");
            if (origin is not null)
            {
                labels["bowerReplayCollectorId"] = origin;
            }
            envelope["labels"] = labels;
            using StringContent content = new(envelope.ToJsonString(), Encoding.UTF8, "application/json");
            string outcome;
            try
            {
                using HttpResponseMessage response = await client.PostAsync("v1/events", content);
                outcome = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
                if (outcome == "400" && (await response.Content.ReadAsStringAsync()).Contains(
                    "archive-replay-collector-mismatch", StringComparison.Ordinal))
                {
                    outcome = CollectorMismatch;
                }
            }
            catch (HttpRequestException)
            {
                outcome = "unreachable";
            }

            responses[outcome] = responses.GetValueOrDefault(outcome) + 1;
            if (IsStop(outcome))
            {
                break;
            }
        }

        output.WriteLine(JsonSerializer.Serialize(
            new ArchiveReplayOutput(selected, dryRun, responses),
            CliJsonContext.Default.ArchiveReplayOutput));
        if (responses.GetValueOrDefault(CollectorMismatch) is > 0 and long skipped)
        {
            error.WriteLine($"{skipped.ToString(CultureInfo.InvariantCulture)} event(s) skipped: their collector differs from the replay collector's BOWER_COLLECTOR_ID. Replay each collector's events with --collector-id through a collector with that id.");
        }

        return responses.Keys.Any(code => IsStop(code) || code == CollectorMismatch) ? 2 : 0;
    }

    /// <summary>Per-event outcome for a replay a collector with another id refused.</summary>
    internal const string CollectorMismatch = "collector-mismatch";

    private static bool IsStop(string outcome) =>
        outcome is "unreachable" or "401" or "403" or "429" || outcome.StartsWith('5');

    internal static LedgerHead? ParseAnchor(string? value)
    {
        if (value is null)
        {
            return null;
        }

        string[] parts = value.Split(':', 2);
        return parts.Length == 2
            && long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long sequence)
            && parts[1].Length == 64
            && parts[1].All(char.IsAsciiHexDigitLower)
                ? new LedgerHead(sequence, parts[1])
                : throw new ArgumentException("--anchor must be SEQUENCE:HASH (64 lower-case hex digits).");
    }
}

internal static class SourceCommands
{
    /// <summary>
    /// bower sources check --expectations FILE [--database FILE]: offline silence check from
    /// the activity and monitoring starts the collector last persisted. Exit 3 when any
    /// expected source is overdue.
    /// </summary>
    public static async Task<int> CheckAsync(string[] args)
    {
        SourceExpectations expectations = SourceExpectationsLoader.LoadFile(CliOptions.Required(args, "--expectations"));
        SqliteEventStore store = await QueueCommands.OpenStoreAsync(args);
        SourcesCheckOutput output = await EvaluateAsync(expectations, store, DateTimeOffset.UtcNow);
        Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.SourcesCheckOutput));
        return output.Healthy ? 0 : 3;
    }

    /// <summary>
    /// Reads, never writes, the collector's monitoring starts, so a source the collector
    /// reports as pending is pending here too. A source the collector never monitored has
    /// no grace period: never seen is reported at once.
    /// </summary>
    internal static async Task<SourcesCheckOutput> EvaluateAsync(
        SourceExpectations expectations,
        SqliteEventStore store,
        DateTimeOffset now)
    {
        IReadOnlyList<SourceSilenceStatus> statuses = SourceSilenceEvaluator.Evaluate(
            expectations,
            await store.GetSourceActivityAsync(),
            await store.GetSourceMonitoringAsync(),
            DateTimeOffset.MinValue,
            now);
        return new SourcesCheckOutput(
            !statuses.Any(item => item.IsOverdue),
            [.. statuses.Select(item => new SourceCheckItem(
                item.Application,
                item.Environment,
                item.State,
                item.LastSeenAt,
                item.LastSeenAt is null ? null : item.SilentSeconds,
                item.AllowedSilenceSeconds))]);
    }
}
