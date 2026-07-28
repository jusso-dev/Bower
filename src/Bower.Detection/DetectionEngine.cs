using System.Text.Json;
using Bower.Contracts;

namespace Bower.Detection;

public sealed class DetectionEngine
{
    private readonly IReadOnlyList<DetectionRule> rules;
    private readonly HashSet<string> suppressedRuleIds;
    private readonly HashSet<string> seenFingerprints = new(StringComparer.Ordinal);

    public DetectionEngine(
        IEnumerable<DetectionRule> rules,
        IEnumerable<string>? suppressedRuleIds = null)
    {
        this.rules = rules.ToArray();
        this.suppressedRuleIds = new HashSet<string>(
            suppressedRuleIds ?? [],
            StringComparer.OrdinalIgnoreCase);
    }

    public static DetectionEngine FromDirectory(
        string directory,
        IEnumerable<string>? suppressedRuleIds = null)
    {
        return new DetectionEngine(SigmaRuleLoader.LoadDirectory(directory), suppressedRuleIds);
    }

    public IReadOnlyList<DetectionRule> Rules => rules;

    public DetectionEvaluationResult Evaluate(SecurityEventEnvelope envelope, DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        DateTimeOffset detectedAt = now ?? DateTimeOffset.UtcNow;
        List<DetectionAlert> alerts = [];
        List<string> suppressed = [];

        foreach (DetectionRule rule in rules)
        {
            if (suppressedRuleIds.Contains(rule.Id))
            {
                suppressed.Add(rule.Id);
                continue;
            }

            if (!Matches(rule, envelope, out List<string> matchedFields))
            {
                continue;
            }

            string fingerprint = $"{rule.Id}:{envelope.EventId}:{rule.RuleHash}";
            if (!seenFingerprints.Add(fingerprint))
            {
                continue;
            }

            alerts.Add(
                new DetectionAlert(
                    Guid.CreateVersion7().ToString(),
                    rule.Id,
                    rule.Title,
                    rule.Version,
                    rule.RuleHash,
                    rule.Level,
                    RiskScore(rule.Level),
                    detectedAt,
                    envelope.EventId,
                    envelope.EventType,
                    envelope.Actor?.Username ?? envelope.Actor?.UserId,
                    envelope.Source?.IpAddress,
                    rule.MitreTechniques,
                    matchedFields,
                    $"{rule.Title} matched event {envelope.EventType} ({envelope.EventAction})"));
        }

        return new DetectionEvaluationResult(alerts, suppressed.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public DetectionEvaluationResult EvaluateJson(string eventJson, DateTimeOffset? now = null)
    {
        SecurityEventEnvelope? envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(
            eventJson,
            BowerJson.Options);
        if (envelope is null)
        {
            throw new InvalidDataException("Event JSON did not deserialize to SecurityEventEnvelope.");
        }

        return Evaluate(envelope, now);
    }

    private static bool Matches(
        DetectionRule rule,
        SecurityEventEnvelope envelope,
        out List<string> matchedFields)
    {
        matchedFields = [];
        Dictionary<string, string> haystack = BuildHaystack(envelope);

        // MVP: condition "selection" or "selection1 or selection2" — all keys under named selection groups.
        string[] groups = rule.Condition
            .Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(token => !token.Equals("or", StringComparison.OrdinalIgnoreCase)
                && !token.Equals("and", StringComparison.OrdinalIgnoreCase)
                && !token.Equals("not", StringComparison.OrdinalIgnoreCase)
                && !token.Equals("1", StringComparison.Ordinal)
                && !token.Equals("of", StringComparison.OrdinalIgnoreCase)
                && !token.Equals("them", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (groups.Length == 0)
        {
            groups = rule.DetectionFields.Keys.ToArray();
        }

        bool anyGroup = rule.Condition.Contains(" or ", StringComparison.OrdinalIgnoreCase)
            || rule.Condition.Contains("1 of them", StringComparison.OrdinalIgnoreCase);

        List<bool> groupResults = [];
        foreach (string group in groups)
        {
            if (!rule.DetectionFields.TryGetValue(group, out string? selection))
            {
                groupResults.Add(false);
                continue;
            }

            bool groupMatch = MatchSelection(selection, haystack, matchedFields);
            groupResults.Add(groupMatch);
        }

        return anyGroup ? groupResults.Any(result => result) : groupResults.All(result => result);
    }

    private static bool MatchSelection(
        string selection,
        IReadOnlyDictionary<string, string> haystack,
        List<string> matchedFields)
    {
        // selection forms: "field:value|value2;field2:value"
        string[] clauses = selection.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (clauses.Length == 0)
        {
            return ContainsIgnoreCase(string.Join(' ', haystack.Values), selection, matchedFields, "payload");
        }

        foreach (string clause in clauses)
        {
            int separator = clause.IndexOf(':');
            if (separator <= 0)
            {
                if (!ContainsIgnoreCase(string.Join(' ', haystack.Values), clause, matchedFields, "payload"))
                {
                    return false;
                }

                continue;
            }

            string field = clause[..separator].Trim().TrimEnd('|', '*');
            string pattern = clause[(separator + 1)..];
            if (!haystack.TryGetValue(field, out string? value))
            {
                // also try event.* aliases
                string? alias = haystack.FirstOrDefault(pair =>
                    pair.Key.EndsWith(field, StringComparison.OrdinalIgnoreCase)).Value;
                if (alias is null)
                {
                    return false;
                }

                value = alias;
            }

            string[] alternatives = pattern.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool matched = alternatives.Any(option =>
                value.Contains(option, StringComparison.OrdinalIgnoreCase));
            if (!matched)
            {
                return false;
            }

            matchedFields.Add(field);
        }

        return true;
    }

    private static bool ContainsIgnoreCase(
        string haystack,
        string needle,
        List<string> matchedFields,
        string fieldName)
    {
        if (haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
        {
            matchedFields.Add(fieldName);
            return true;
        }

        return false;
    }

    private static Dictionary<string, string> BuildHaystack(SecurityEventEnvelope envelope)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase)
        {
            ["EventType"] = envelope.EventType,
            ["EventAction"] = envelope.EventAction,
            ["EventCategory"] = envelope.EventCategory,
            ["EventResult"] = envelope.EventResult.ToString(),
            ["EventOutcomeReason"] = envelope.EventOutcomeReason ?? string.Empty,
            ["ActorUsername"] = envelope.Actor?.Username ?? string.Empty,
            ["ActorUserId"] = envelope.Actor?.UserId ?? string.Empty,
            ["SourceIp"] = envelope.Source?.IpAddress ?? string.Empty,
            ["TargetName"] = envelope.Target?.Name ?? string.Empty,
            ["TargetType"] = envelope.Target?.Type ?? string.Empty,
            ["Application"] = envelope.Application.Name
        };

        if (envelope.Labels is not null)
        {
            foreach ((string key, string value) in envelope.Labels)
            {
                values[key] = value;
            }
        }

        return values;
    }

    private static int RiskScore(string level)
    {
        return level.ToLowerInvariant() switch
        {
            "informational" => 10,
            "low" => 25,
            "medium" => 50,
            "high" => 75,
            "critical" => 95,
            _ => 40
        };
    }
}
