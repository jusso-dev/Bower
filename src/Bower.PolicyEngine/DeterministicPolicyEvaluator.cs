using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.PolicyEngine;

public sealed class DeterministicPolicyEvaluator : ITelemetryPolicyEvaluator
{
    private readonly IReadOnlyList<LoadedPolicy> policies;

    public DeterministicPolicyEvaluator(IEnumerable<LoadedPolicy> policies)
    {
        this.policies = policies
            .OrderBy(item => item.Policy.Metadata.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public PolicyDecision Evaluate(SecurityEventEnvelope candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        LoadedPolicy? loaded = policies.FirstOrDefault(item => Matches(item.Policy.Match, candidate));
        if (loaded is null)
        {
            return new PolicyDecision(
                DecisionAction.Reject,
                "BWR-POL-DEFAULT-DENY",
                "1.0.0",
                "builtin:default-deny-v1",
                0,
                ["No approved policy matched event category and type"],
                []);
        }

        TelemetryPolicy policy = loaded.Policy;
        List<string> missingRequired = policy.Requirements.RequiredFields
            .Where(path => !EventFieldReader.HasValue(candidate, path))
            .ToList();

        bool hasAtLeastOne = policy.Requirements.AtLeastOne.Count == 0
            || policy.Requirements.AtLeastOne.Any(path => EventFieldReader.HasValue(candidate, path));
        if (!hasAtLeastOne)
        {
            missingRequired.Add($"one-of({string.Join(",", policy.Requirements.AtLeastOne)})");
        }

        if (missingRequired.Count > 0)
        {
            return new PolicyDecision(
                DecisionAction.Quarantine,
                policy.Metadata.Id,
                policy.Metadata.Version,
                loaded.Hash,
                CalculateScore(candidate, policy, missingRequired.Count),
                missingRequired.Select(path => $"Missing required field: {path}").ToArray(),
                []);
        }

        int score = CalculateScore(candidate, policy, 0);
        List<string> reasons =
        [
            $"Approved semantic event type: {candidate.EventType}",
            "All required investigation fields present"
        ];
        List<string> warnings = policy.Requirements.RecommendedFields
            .Where(path => !EventFieldReader.HasValue(candidate, path))
            .Select(path => $"Missing recommended field: {path}")
            .ToList();

        DecisionAction configuredAction = ParseAction(policy.Decision.Action);
        DecisionAction action = score < policy.Decision.MinimumValueScore
            ? DecisionAction.Reject
            : configuredAction;

        if (score < policy.Decision.MinimumValueScore)
        {
            reasons.Add(
                $"Value score {score} is below minimum {policy.Decision.MinimumValueScore}");
        }
        else
        {
            reasons.Add($"Value score {score} meets minimum {policy.Decision.MinimumValueScore}");
        }

        return new PolicyDecision(
            action,
            policy.Metadata.Id,
            policy.Metadata.Version,
            loaded.Hash,
            score,
            reasons,
            warnings);
    }

    private static bool Matches(PolicyMatch match, SecurityEventEnvelope candidate)
    {
        bool categoryMatch = match.EventCategories.Count == 0
            || match.EventCategories.Contains(candidate.EventCategory, StringComparer.Ordinal);
        bool typeMatch = match.EventTypes.Count == 0
            || match.EventTypes.Contains(candidate.EventType, StringComparer.Ordinal);
        return categoryMatch && typeMatch;
    }

    private static int CalculateScore(
        SecurityEventEnvelope candidate,
        TelemetryPolicy policy,
        int missingRequiredCount)
    {
        int score = 40;
        score += Math.Max(0, 30 - (missingRequiredCount * 15));
        score += candidate.Actor is not null ? 10 : 0;
        score += candidate.Target is not null ? 5 : 0;
        score += candidate.Source is not null ? 5 : 0;
        score += !string.IsNullOrWhiteSpace(candidate.Request?.CorrelationId) ? 10 : 0;

        int recommendedPresent = policy.Requirements.RecommendedFields.Count(path =>
            EventFieldReader.HasValue(candidate, path));
        score += Math.Min(5, recommendedPresent);
        return Math.Min(100, score);
    }

    private static DecisionAction ParseAction(string value)
    {
        string normalized = value.Replace("-", string.Empty, StringComparison.Ordinal);
        return Enum.Parse<DecisionAction>(normalized, true);
    }
}
