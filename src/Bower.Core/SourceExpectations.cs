using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;

namespace Bower.Core;

/// <summary>
/// Applications that must keep sending security events, with the longest acceptable silence
/// for each. A silent source means the SIEM is blind to it.
/// </summary>
public sealed record SourceExpectations(
    string ApiVersion,
    string Kind,
    IReadOnlyList<SourceExpectation> Sources);

public sealed record SourceExpectation(
    string Application,
    string Environment,
    int MaximumSilenceMinutes);

public static class SourceExpectationsLoader
{
    public const int MaximumSources = 1_000;
    public const int MaximumSilenceMinutesLimit = 10_080;
    private const int MaximumBytes = 262_144;

    public static SourceExpectations LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Source expectations file does not exist.", path);
        }

        if (info.Length > MaximumBytes)
        {
            throw new InvalidDataException("Source expectations file exceeds 256 KiB.");
        }

        return Parse(File.ReadAllText(path));
    }

    public static SourceExpectations Parse(string json)
    {
        SourceExpectations? expectations;
        try
        {
            expectations = JsonSerializer.Deserialize(json, SourceExpectationsJsonContext.Default.SourceExpectations);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Source expectations are invalid: {exception.Message}", exception);
        }

        if (expectations is null
            || !string.Equals(expectations.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(expectations.Kind, "SourceExpectations", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Source expectations need apiVersion bower.security/v1 and kind SourceExpectations.");
        }

        if (expectations.Sources is not { Count: >= 1 and <= MaximumSources })
        {
            throw new InvalidDataException($"Source expectations must list 1–{MaximumSources} sources.");
        }

        HashSet<(string, string)> seen = [];
        foreach (SourceExpectation source in expectations.Sources)
        {
            if (source is null
                || string.IsNullOrWhiteSpace(source.Application)
                || string.IsNullOrWhiteSpace(source.Environment))
            {
                throw new InvalidDataException("Each expected source needs an application and an environment.");
            }

            if (source.MaximumSilenceMinutes is < 1 or > MaximumSilenceMinutesLimit)
            {
                throw new InvalidDataException(
                    $"maximumSilenceMinutes must be between 1 and {MaximumSilenceMinutesLimit}.");
            }

            if (!seen.Add((source.Application, source.Environment)))
            {
                throw new InvalidDataException(
                    $"Expected source {source.Application}/{source.Environment} is listed more than once.");
            }
        }

        return expectations;
    }
}

public static class SourceSilenceEvaluator
{
    /// <summary>
    /// Compares expected sources with observed activity. A source never seen runs its
    /// allowance from its durable monitoring start in <paramref name="monitoring"/>, or from
    /// <paramref name="monitoringSince"/> when it has none: <c>pending</c> while inside the
    /// allowance, then <c>never-seen</c>. A restart therefore cannot extend the deadline.
    /// </summary>
    public static IReadOnlyList<SourceSilenceStatus> Evaluate(
        SourceExpectations expectations,
        IReadOnlyList<SourceActivity> activity,
        IReadOnlyList<SourceMonitoring> monitoring,
        DateTimeOffset monitoringSince,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(expectations);
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(monitoring);

        Dictionary<(string, string), SourceActivity> byKey = [];
        foreach (SourceActivity item in activity)
        {
            byKey[(item.Application, item.Environment)] = item;
        }

        Dictionary<(string, string), DateTimeOffset> started = [];
        foreach (SourceMonitoring item in monitoring)
        {
            started[(item.Application, item.Environment)] = item.MonitoringSince;
        }

        return expectations.Sources
            .Select(expected =>
            {
                long allowed = expected.MaximumSilenceMinutes * 60L;
                (string, string) key = (expected.Application, expected.Environment);
                byKey.TryGetValue(key, out SourceActivity? seen);
                DateTimeOffset reference = seen?.LastSeenAt
                    ?? (started.TryGetValue(key, out DateTimeOffset since) ? since : monitoringSince);
                long silent = Math.Max(0, (long)Math.Floor((now - reference).TotalSeconds));
                string state = (silent <= allowed, seen is null) switch
                {
                    (true, false) => "active",
                    (true, true) => "pending",
                    (false, true) => "never-seen",
                    (false, false) => "silent"
                };
                return new SourceSilenceStatus(
                    expected.Application,
                    expected.Environment,
                    state,
                    seen?.LastSeenAt,
                    silent,
                    allowed);
            })
            .ToArray();
    }
}

/// <param name="State">
/// <c>active</c> (seen within the allowance), <c>pending</c> (not yet seen, still within the
/// allowance from its monitoring start), <c>silent</c> or <c>never-seen</c> (overdue).
/// </param>
public sealed record SourceSilenceStatus(
    string Application,
    string Environment,
    string State,
    DateTimeOffset? LastSeenAt,
    long SilentSeconds,
    long AllowedSilenceSeconds)
{
    /// <summary>Seen within its allowance. A <c>pending</c> source is not active: it has no evidence yet.</summary>
    [JsonIgnore]
    public bool IsActive => State == "active";

    /// <summary>Past its allowance: <c>silent</c> or <c>never-seen</c>.</summary>
    [JsonIgnore]
    public bool IsOverdue => State is "silent" or "never-seen";
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(SourceExpectations))]
internal sealed partial class SourceExpectationsJsonContext : JsonSerializerContext;
