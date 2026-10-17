//! `PackDiff`: population diff between two pack versions. Which event types become
//! accepted or rejected, and which requirements or thresholds change. Required for
//! policy review; a changed policy without a version bump is reported.

use std::collections::HashSet;

use bower_policy::LoadedPolicy;

use crate::archive::{LoadedPack, PackError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyChange {
    pub policy_id: String,
    pub change: String,
    pub detail: String,
}

fn change(id: &str, kind: &str, detail: String) -> PolicyChange {
    PolicyChange {
        policy_id: id.to_owned(),
        change: kind.to_owned(),
        detail,
    }
}

/// `ToDictionary` by policy id: insertion order kept, duplicate ids rejected.
fn by_id(pack: &LoadedPack) -> Result<Vec<(&str, &LoadedPolicy)>, PackError> {
    let mut policies: Vec<(&str, &LoadedPolicy)> = Vec::with_capacity(pack.policies.len());
    for policy in &pack.policies {
        let id = policy.policy.metadata.id.as_str();
        if policies.iter().any(|(existing, _)| *existing == id) {
            return Err(PackError::InvalidData(format!(
                "Pack contains policy '{id}' more than once."
            )));
        }
        policies.push((id, policy));
    }
    Ok(policies)
}

/// `Enumerable.Except`: distinct items of `left` not in `right`, in `left` order.
fn except<'a>(left: &'a [String], right: &[String]) -> Vec<&'a str> {
    let excluded: HashSet<&str> = right.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    left.iter()
        .map(String::as_str)
        .filter(|item| !excluded.contains(item) && seen.insert(*item))
        .collect()
}

fn find<'a>(policies: &[(&str, &'a LoadedPolicy)], id: &str) -> Option<&'a LoadedPolicy> {
    policies
        .iter()
        .find(|(existing, _)| *existing == id)
        .map(|(_, policy)| *policy)
}

pub fn compare(before: &LoadedPack, after: &LoadedPack) -> Result<Vec<PolicyChange>, PackError> {
    let old = by_id(before)?;
    let updated = by_id(after)?;
    let mut changes = Vec::new();

    for (id, policy) in updated.iter().filter(|(id, _)| find(&old, id).is_none()) {
        changes.push(change(
            id,
            "policy-added",
            format!("Accepts {}.", policy.policy.r#match.event_types.join(", ")),
        ));
    }

    for (id, policy) in old.iter().filter(|(id, _)| find(&updated, id).is_none()) {
        changes.push(change(
            id,
            "policy-removed",
            format!(
                "Stops accepting {}.",
                policy.policy.r#match.event_types.join(", ")
            ),
        ));
    }

    for (id, current) in &updated {
        let Some(previous) = find(&old, id) else {
            continue;
        };
        let (a, b) = (&previous.policy, &current.policy);
        for added in except(&b.r#match.event_types, &a.r#match.event_types) {
            changes.push(change(id, "event-type-added", added.to_owned()));
        }
        for removed in except(&a.r#match.event_types, &b.r#match.event_types) {
            changes.push(change(id, "event-type-removed", removed.to_owned()));
        }
        for added in except(
            &b.requirements.required_fields,
            &a.requirements.required_fields,
        ) {
            changes.push(change(
                id,
                "required-field-added",
                format!("{added} (events without it are now quarantined)"),
            ));
        }
        for removed in except(
            &a.requirements.required_fields,
            &b.requirements.required_fields,
        ) {
            changes.push(change(id, "required-field-removed", removed.to_owned()));
        }
        if !eq_ignore_case(&a.decision.action, &b.decision.action) {
            changes.push(change(
                id,
                "action-changed",
                format!("{} -> {}", a.decision.action, b.decision.action),
            ));
        }
        if a.decision.minimum_value_score != b.decision.minimum_value_score {
            changes.push(change(
                id,
                "minimum-score-changed",
                format!(
                    "{} -> {}",
                    a.decision.minimum_value_score, b.decision.minimum_value_score
                ),
            ));
        }
        if a.metadata.version == b.metadata.version && previous.hash != current.hash {
            changes.push(change(
                id,
                "version-not-bumped",
                "Policy content changed without a version bump.".to_owned(),
            ));
        }
    }

    Ok(changes)
}

/// `StringComparison.OrdinalIgnoreCase` (simple case folding per char).
fn eq_ignore_case(left: &str, right: &str) -> bool {
    left.chars()
        .flat_map(char::to_uppercase)
        .eq(right.chars().flat_map(char::to_uppercase))
}
