using Bower.PolicyEngine;

namespace Bower.Packs;

public sealed record PolicyChange(string PolicyId, string Change, string Detail);

/// <summary>
/// Population diff between two pack versions: which event types become accepted or
/// rejected, and which requirements or thresholds change. Required for policy review.
/// </summary>
public static class PackDiff
{
    public static IReadOnlyList<PolicyChange> Compare(LoadedPack before, LoadedPack after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        Dictionary<string, LoadedPolicy> old = before.Policies.ToDictionary(item => item.Policy.Metadata.Id, StringComparer.Ordinal);
        Dictionary<string, LoadedPolicy> updated = after.Policies.ToDictionary(item => item.Policy.Metadata.Id, StringComparer.Ordinal);
        List<PolicyChange> changes = [];

        foreach ((string id, LoadedPolicy policy) in updated.Where(item => !old.ContainsKey(item.Key)))
        {
            changes.Add(new(id, "policy-added", $"Accepts {string.Join(", ", policy.Policy.Match.EventTypes)}."));
        }

        foreach ((string id, LoadedPolicy policy) in old.Where(item => !updated.ContainsKey(item.Key)))
        {
            changes.Add(new(id, "policy-removed", $"Stops accepting {string.Join(", ", policy.Policy.Match.EventTypes)}."));
        }

        foreach ((string id, LoadedPolicy current) in updated.Where(item => old.ContainsKey(item.Key)))
        {
            TelemetryPolicy a = old[id].Policy;
            TelemetryPolicy b = current.Policy;
            foreach (string added in b.Match.EventTypes.Except(a.Match.EventTypes, StringComparer.Ordinal))
            {
                changes.Add(new(id, "event-type-added", added));
            }

            foreach (string removed in a.Match.EventTypes.Except(b.Match.EventTypes, StringComparer.Ordinal))
            {
                changes.Add(new(id, "event-type-removed", removed));
            }

            foreach (string added in b.Requirements.RequiredFields.Except(a.Requirements.RequiredFields, StringComparer.Ordinal))
            {
                changes.Add(new(id, "required-field-added", $"{added} (events without it are now quarantined)"));
            }

            foreach (string removed in a.Requirements.RequiredFields.Except(b.Requirements.RequiredFields, StringComparer.Ordinal))
            {
                changes.Add(new(id, "required-field-removed", removed));
            }

            if (!string.Equals(a.Decision.Action, b.Decision.Action, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add(new(id, "action-changed", $"{a.Decision.Action} -> {b.Decision.Action}"));
            }

            if (a.Decision.MinimumValueScore != b.Decision.MinimumValueScore)
            {
                changes.Add(new(id, "minimum-score-changed", $"{a.Decision.MinimumValueScore} -> {b.Decision.MinimumValueScore}"));
            }

            if (string.Equals(a.Metadata.Version, b.Metadata.Version, StringComparison.Ordinal)
                && !string.Equals(old[id].Hash, current.Hash, StringComparison.Ordinal))
            {
                changes.Add(new(id, "version-not-bumped", "Policy content changed without a version bump."));
            }
        }

        return changes;
    }
}
