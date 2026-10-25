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
    /// Compares expected sources with observed activity. A source never seen is silent once
    /// its allowance has passed since <paramref name="monitoringSince"/>, so a fresh start does
    /// not raise immediate false alarms.
    /// </summary>
    public static IReadOnlyList<SourceSilenceStatus> Evaluate(
        SourceExpectations expectations,
        IReadOnlyList<SourceActivity> activity,
        DateTimeOffset monitoringSince,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(expectations);
        ArgumentNullException.ThrowIfNull(activity);

        Dictionary<(string, string), SourceActivity> byKey = [];
        foreach (SourceActivity item in activity)
        {
            byKey[(item.Application, item.Environment)] = item;
        }

        return expectations.Sources
            .Select(expected =>
            {
                long allowed = expected.MaximumSilenceMinutes * 60L;
                byKey.TryGetValue((expected.Application, expected.Environment), out SourceActivity? seen);
                DateTimeOffset reference = seen?.LastSeenAt ?? monitoringSince;
                long silent = Math.Max(0, (long)Math.Floor((now - reference).TotalSeconds));
                string state = silent <= allowed ? "active" : seen is null ? "never-seen" : "silent";
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

/// <param name="State"><c>active</c>, <c>silent</c> or <c>never-seen</c>.</param>
public sealed record SourceSilenceStatus(
    string Application,
    string Environment,
    string State,
    DateTimeOffset? LastSeenAt,
    long SilentSeconds,
    long AllowedSilenceSeconds)
{
    [JsonIgnore]
    public bool IsActive => State == "active";
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(SourceExpectations))]
internal sealed partial class SourceExpectationsJsonContext : JsonSerializerContext;
