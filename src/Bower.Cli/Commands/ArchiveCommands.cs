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
    ///   [--event-type TYPE]... [--dry-run]
    /// Verifies the archive, then posts selected events through a collector's full intake
    /// labelled <c>bowerReplay: archive</c>. Sends BOWER_INGEST_TOKEN when set. Use a collector
    /// with its own queue: the original queue reports replayed events as duplicates.
    /// </summary>
    public static async Task<int> ReplayAsync(string[] args)
    {
        QueueArchive archive = new(CliOptions.Required(args, "--archive"), "replay");
        ArchiveVerification verification = await archive.VerifyAsync();
        if (!verification.Intact)
        {
            Console.WriteLine(JsonSerializer.Serialize(ArchiveVerifyOutput.From(verification), CliJsonContext.Default.ArchiveVerifyOutput));
            Console.Error.WriteLine("Archive failed verification; replay refused.");
            return 3;
        }

        DateTimeOffset? from = CliOptions.Timestamp(CliOptions.Get(args, "--from"), "--from");
        DateTimeOffset? to = CliOptions.Timestamp(CliOptions.Get(args, "--to"), "--to");
        HashSet<string> eventTypes = CliOptions.All(args, "--event-type").ToHashSet(StringComparer.Ordinal);
        bool dryRun = CliOptions.Has(args, "--dry-run");
        string collector = CliOptions.Required(args, "--collector-url");
        using HttpClient client = new()
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
            if ((from is not null && generated < from)
                || (to is not null && generated >= to)
                || (eventTypes.Count > 0 && !eventTypes.Contains(eventType)))
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
            envelope["labels"] = labels;
            using StringContent content = new(envelope.ToJsonString(), Encoding.UTF8, "application/json");
            string outcome;
            try
            {
                using HttpResponseMessage response = await client.PostAsync("v1/events", content);
                outcome = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
            }
            catch (HttpRequestException)
            {
                outcome = "unreachable";
            }

            responses[outcome] = responses.GetValueOrDefault(outcome) + 1;
            if (outcome is "unreachable" or "401" or "403" or "429" || outcome.StartsWith('5'))
            {
                break;
            }
        }

        Console.WriteLine(JsonSerializer.Serialize(
            new ArchiveReplayOutput(selected, dryRun, responses),
            CliJsonContext.Default.ArchiveReplayOutput));
        return responses.Keys.Any(code => code is "unreachable" or "401" or "403" or "429" || code.StartsWith('5')) ? 2 : 0;
    }

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
