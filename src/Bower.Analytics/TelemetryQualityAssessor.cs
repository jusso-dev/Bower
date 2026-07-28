using Bower.Contracts;

namespace Bower.Analytics;

public sealed record SourceCoverageObservation(
    string SourceId,
    string SourceType,
    bool Healthy,
    DateTimeOffset? LastEventAt,
    long EventsObserved,
    bool Required);

public sealed record FieldCompletenessObservation(
    string FieldName,
    long PresentCount,
    long TotalCount,
    bool Required);

public sealed record QualityAssessmentInput(
    IReadOnlyList<SourceCoverageObservation> Sources,
    IReadOnlyList<FieldCompletenessObservation> Fields,
    IReadOnlyList<SecurityEventEnvelope>? SampleEvents = null,
    TimeSpan? FreshnessWindow = null);

public sealed record QualityComponentScore(
    string Name,
    int Score,
    int Weight,
    string Summary,
    IReadOnlyList<string> Evidence);

public sealed record TelemetryQualityReport(
    int OverallScore,
    string Grade,
    IReadOnlyList<QualityComponentScore> Components,
    IReadOnlyList<string> Recommendations,
    DateTimeOffset AssessedAt);

public static class TelemetryQualityAssessor
{
    public static TelemetryQualityReport Assess(
        QualityAssessmentInput input,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        DateTimeOffset assessedAt = now ?? DateTimeOffset.UtcNow;
        TimeSpan freshnessWindow = input.FreshnessWindow ?? TimeSpan.FromHours(24);

        QualityComponentScore coverage = ScoreCoverage(input.Sources, assessedAt, freshnessWindow);
        QualityComponentScore completeness = ScoreCompleteness(input.Fields);
        QualityComponentScore freshness = ScoreFreshness(input.Sources, assessedAt, freshnessWindow);
        QualityComponentScore schema = ScoreSchema(input.SampleEvents ?? []);

        QualityComponentScore[] components = [coverage, completeness, freshness, schema];
        int totalWeight = components.Sum(item => item.Weight);
        int overall = totalWeight == 0
            ? 0
            : (int)Math.Round(
                components.Sum(item => item.Score * item.Weight) / (double)totalWeight,
                MidpointRounding.AwayFromZero);

        List<string> recommendations = [];
        foreach (QualityComponentScore component in components.Where(item => item.Score < 70))
        {
            recommendations.AddRange(component.Evidence.Select(item => $"{component.Name}: {item}"));
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add("Telemetry quality is within target thresholds.");
        }

        return new TelemetryQualityReport(
            overall,
            Grade(overall),
            components,
            recommendations,
            assessedAt);
    }

    private static QualityComponentScore ScoreCoverage(
        IReadOnlyList<SourceCoverageObservation> sources,
        DateTimeOffset now,
        TimeSpan freshnessWindow)
    {
        if (sources.Count == 0)
        {
            return new QualityComponentScore(
                "coverage",
                0,
                30,
                "No sources configured.",
                ["Register required security sources."]);
        }

        SourceCoverageObservation[] required = sources.Where(item => item.Required).ToArray();
        IReadOnlyList<SourceCoverageObservation> basis = required.Length > 0 ? required : sources;
        int covered = basis.Count(item =>
            item.Healthy &&
            item.EventsObserved > 0 &&
            item.LastEventAt is { } last &&
            now - last <= freshnessWindow);
        int score = (int)Math.Round(100.0 * covered / basis.Count, MidpointRounding.AwayFromZero);
        List<string> evidence = basis
            .Where(item => !(item.Healthy && item.EventsObserved > 0))
            .Select(item => $"Source '{item.SourceId}' ({item.SourceType}) not contributing.")
            .Take(5)
            .ToList();

        return new QualityComponentScore(
            "coverage",
            score,
            30,
            $"{covered}/{basis.Count} required sources healthy with recent events.",
            evidence);
    }

    private static QualityComponentScore ScoreCompleteness(
        IReadOnlyList<FieldCompletenessObservation> fields)
    {
        FieldCompletenessObservation[] required = fields
            .Where(item => item.Required && item.TotalCount > 0)
            .ToArray();
        if (required.Length == 0)
        {
            return new QualityComponentScore(
                "completeness",
                50,
                25,
                "No required field observations supplied.",
                ["Provide field completeness samples for actor, action, target and correlation."]);
        }

        double average = required.Average(item => 100.0 * item.PresentCount / item.TotalCount);
        int score = (int)Math.Round(average, MidpointRounding.AwayFromZero);
        List<string> evidence = required
            .Where(item => item.PresentCount * 100.0 / item.TotalCount < 80)
            .Select(item =>
                $"Field '{item.FieldName}' present in {item.PresentCount}/{item.TotalCount} events.")
            .Take(5)
            .ToList();

        return new QualityComponentScore(
            "completeness",
            score,
            25,
            "Average required-field fill rate.",
            evidence);
    }

    private static QualityComponentScore ScoreFreshness(
        IReadOnlyList<SourceCoverageObservation> sources,
        DateTimeOffset now,
        TimeSpan freshnessWindow)
    {
        SourceCoverageObservation[] withEvents = sources
            .Where(item => item.LastEventAt is not null)
            .ToArray();
        if (withEvents.Length == 0)
        {
            return new QualityComponentScore(
                "freshness",
                0,
                25,
                "No source timestamps available.",
                ["Confirm collectors are emitting heartbeats and events."]);
        }

        int fresh = withEvents.Count(item => now - item.LastEventAt! <= freshnessWindow);
        int score = (int)Math.Round(100.0 * fresh / withEvents.Length, MidpointRounding.AwayFromZero);
        List<string> evidence = withEvents
            .Where(item => now - item.LastEventAt! > freshnessWindow)
            .Select(item => $"Source '{item.SourceId}' last event at {item.LastEventAt:O}.")
            .Take(5)
            .ToList();

        return new QualityComponentScore(
            "freshness",
            score,
            25,
            $"{fresh}/{withEvents.Length} sources within freshness window {freshnessWindow}.",
            evidence);
    }

    private static QualityComponentScore ScoreSchema(IReadOnlyList<SecurityEventEnvelope> events)
    {
        if (events.Count == 0)
        {
            return new QualityComponentScore(
                "schema",
                50,
                20,
                "No sample events supplied for schema quality.",
                ["Include sample events to score actor/target/correlation completeness."]);
        }

        int points = 0;
        int total = events.Count * 4;
        foreach (SecurityEventEnvelope envelope in events)
        {
            if (!string.IsNullOrWhiteSpace(envelope.Actor?.Username) ||
                !string.IsNullOrWhiteSpace(envelope.Actor?.UserId))
            {
                points++;
            }

            if (envelope.Target is not null)
            {
                points++;
            }

            if (envelope.Request?.CorrelationId is not null || envelope.Request?.TraceId is not null)
            {
                points++;
            }

            if (!string.IsNullOrWhiteSpace(envelope.EventAction))
            {
                points++;
            }
        }

        int score = (int)Math.Round(100.0 * points / total, MidpointRounding.AwayFromZero);
        List<string> evidence = [];
        if (score < 80)
        {
            evidence.Add("Increase actor, target, correlation and action population on emitted events.");
        }

        return new QualityComponentScore(
            "schema",
            score,
            20,
            "Semantic field population across sample events.",
            evidence);
    }

    private static string Grade(int score)
    {
        return score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
    }
}
