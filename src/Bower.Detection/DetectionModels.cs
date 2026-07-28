namespace Bower.Detection;

public sealed record DetectionRule(
    string Id,
    string Title,
    string Version,
    string Level,
    string Status,
    string Description,
    IReadOnlyList<string> LogSources,
    IReadOnlyDictionary<string, string> DetectionFields,
    string Condition,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<string> FalsePositiveHints,
    string RuleHash);

public sealed record DetectionAlert(
    string AlertId,
    string RuleId,
    string RuleTitle,
    string RuleVersion,
    string RuleHash,
    string Level,
    int RiskScore,
    DateTimeOffset DetectedAt,
    string EventId,
    string? EventType,
    string? Actor,
    string? SourceIp,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<string> MatchedFields,
    string Summary);

public sealed record DetectionEvaluationResult(
    IReadOnlyList<DetectionAlert> Alerts,
    IReadOnlyList<string> SuppressedRuleIds);
