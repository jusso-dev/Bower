using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.PolicyEngine;

public sealed class DeterministicPolicyEvaluator : ITelemetryPolicyEvaluator
{
    private readonly LoadedPolicy[] policies;

    public DeterministicPolicyEvaluator(IEnumerable<LoadedPolicy> policies)
    {
        this.policies = policies
            .OrderBy(item => item.Policy.Metadata.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public PolicyDecision Evaluate(SecurityEventEnvelope candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        // Plain loop over the id-ordered array: same first-match result without a closure
        // and enumerator allocation per event.
        LoadedPolicy? loaded = null;
        foreach (LoadedPolicy item in policies)
        {
            if (Matches(item.Policy.Match, candidate))
            {
                loaded = item;
                break;
            }
        }
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

        SuppressionDirective? suppression =
            action is DecisionAction.Accept or DecisionAction.RedactAndAccept
            && policy.Suppression is { } rule
                ? new SuppressionDirective(
                    rule.KeyFields,
                    rule.KeyFields.Select(path => EventFieldReader.GetSuppressionKeyValue(candidate, path)).ToArray(),
                    rule.WindowSeconds,
                    rule.AllowPerWindow)
                : null;

        return new PolicyDecision(
            action,
            policy.Metadata.Id,
            policy.Metadata.Version,
            loaded.Hash,
            score,
            reasons,
            warnings,
            suppression);
    }

    private static bool Matches(PolicyMatch match, SecurityEventEnvelope candidate)
    {
        // Event types are mandatory (enforced by PolicyLoader); an empty list never matches,
        // so unknown types stay default-deny even for hand-built policies.
        // List<string>.Contains uses ordinal string equality without boxing an enumerator.
        bool categoryMatch = match.EventCategories.Count == 0
            || match.EventCategories.Contains(candidate.EventCategory);
        bool typeMatch = match.EventTypes.Contains(candidate.EventType);
        return categoryMatch && typeMatch
            && (match.EventActions is null || match.EventActions.Contains(candidate.EventAction))
            && (match.EventResults is null || match.EventResults.Contains(candidate.EventResult.ToString().ToLowerInvariant()))
            && (match.EventSeverities is null || match.EventSeverities.Contains(candidate.EventSeverity.ToString().ToLowerInvariant()));
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

    private static DecisionAction ParseAction(string value) =>
        PolicyLoader.TryParseAction(value, out DecisionAction action)
            ? action
            : DecisionAction.Reject;
}
