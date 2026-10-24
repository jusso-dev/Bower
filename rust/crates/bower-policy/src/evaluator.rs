//! Port of `DeterministicPolicyEvaluator`.

use bower_contracts::{
    DecisionAction, PolicyDecision, SecurityEventEnvelope, TelemetryPolicyEvaluator,
};

use crate::field::{has_value, present};
use crate::loader::{ordinal_cmp, try_parse_action};
use crate::model::{LoadedPolicy, PolicyMatch, TelemetryPolicy};

pub const DEFAULT_DENY_POLICY_ID: &str = "BWR-POL-DEFAULT-DENY";
pub const DEFAULT_DENY_POLICY_VERSION: &str = "1.0.0";
pub const DEFAULT_DENY_POLICY_HASH: &str = "builtin:default-deny-v1";

/// First matching policy (ordered by id, ordinal) decides; no match is a
/// default-deny reject.
#[derive(Clone, Debug)]
pub struct DeterministicPolicyEvaluator {
    policies: Vec<LoadedPolicy>,
}

impl DeterministicPolicyEvaluator {
    pub fn new(policies: impl IntoIterator<Item = LoadedPolicy>) -> Self {
        let mut policies: Vec<LoadedPolicy> = policies.into_iter().collect();
        // Stable, like LINQ OrderBy with StringComparer.Ordinal.
        policies.sort_by(|left, right| {
            ordinal_cmp(&left.policy.metadata.id, &right.policy.metadata.id)
        });
        Self { policies }
    }

    pub fn policies(&self) -> &[LoadedPolicy] {
        &self.policies
    }
}

impl TelemetryPolicyEvaluator for DeterministicPolicyEvaluator {
    fn evaluate(&self, candidate: &SecurityEventEnvelope) -> PolicyDecision {
        let Some(loaded) = self
            .policies
            .iter()
            .find(|item| matches(&item.policy.r#match, candidate))
        else {
            return PolicyDecision {
                action: DecisionAction::Reject,
                policy_id: DEFAULT_DENY_POLICY_ID.to_owned(),
                policy_version: DEFAULT_DENY_POLICY_VERSION.to_owned(),
                policy_hash: DEFAULT_DENY_POLICY_HASH.to_owned(),
                score: 0,
                reasons: vec!["No approved policy matched event category and type".to_owned()],
                warnings: Vec::new(),
            };
        };

        let policy = &loaded.policy;
        let requirements = &policy.requirements;
        let mut missing_required: Vec<String> = requirements
            .required_fields
            .iter()
            .filter(|path| !has_value(candidate, path))
            .cloned()
            .collect();

        let has_at_least_one = requirements.at_least_one.is_empty()
            || requirements
                .at_least_one
                .iter()
                .any(|path| has_value(candidate, path));
        if !has_at_least_one {
            missing_required.push(format!("one-of({})", requirements.at_least_one.join(",")));
        }

        if !missing_required.is_empty() {
            return PolicyDecision {
                action: DecisionAction::Quarantine,
                policy_id: policy.metadata.id.clone(),
                policy_version: policy.metadata.version.clone(),
                policy_hash: loaded.hash.clone(),
                score: calculate_score(candidate, policy, missing_required.len()),
                reasons: missing_required
                    .iter()
                    .map(|path| format!("Missing required field: {path}"))
                    .collect(),
                warnings: Vec::new(),
            };
        }

        let score = calculate_score(candidate, policy, 0);
        let mut reasons = vec![
            format!("Approved semantic event type: {}", candidate.event_type),
            "All required investigation fields present".to_owned(),
        ];
        let warnings: Vec<String> = requirements
            .recommended_fields
            .iter()
            .filter(|path| !has_value(candidate, path))
            .map(|path| format!("Missing recommended field: {path}"))
            .collect();

        let minimum = policy.decision.minimum_value_score;
        let action = if score < minimum {
            reasons.push(format!("Value score {score} is below minimum {minimum}"));
            DecisionAction::Reject
        } else {
            reasons.push(format!("Value score {score} meets minimum {minimum}"));
            try_parse_action(Some(&policy.decision.action)).unwrap_or(DecisionAction::Reject)
        };

        PolicyDecision {
            action,
            policy_id: policy.metadata.id.clone(),
            policy_version: policy.metadata.version.clone(),
            policy_hash: loaded.hash.clone(),
            score,
            reasons,
            warnings,
        }
    }
}

/// Event types are mandatory (enforced by the loader); an empty list never
/// matches, so unknown types stay default-deny even for hand-built policies.
fn matches(rule: &PolicyMatch, candidate: &SecurityEventEnvelope) -> bool {
    let category_match = rule.event_categories.is_empty()
        || rule.event_categories.contains(&candidate.event_category);
    let type_match = rule.event_types.contains(&candidate.event_type);
    category_match
        && type_match
        && rule
            .event_actions
            .as_ref()
            .is_none_or(|values| values.contains(&candidate.event_action))
        && rule.event_results.as_ref().is_none_or(|values| {
            values.contains(&candidate.event_result.pascal_name().to_lowercase())
        })
        && rule.event_severities.as_ref().is_none_or(|values| {
            values.contains(&candidate.event_severity.pascal_name().to_lowercase())
        })
}

fn calculate_score(
    candidate: &SecurityEventEnvelope,
    policy: &TelemetryPolicy,
    missing_required_count: usize,
) -> i32 {
    let missing = i64::try_from(missing_required_count).unwrap_or(i64::MAX);
    let mut score: i64 = 40;
    score += 30_i64.saturating_sub(missing.saturating_mul(15)).max(0);
    score += if candidate.actor.is_some() { 10 } else { 0 };
    score += if candidate.target.is_some() { 5 } else { 0 };
    score += if candidate.source.is_some() { 5 } else { 0 };
    let correlation = candidate
        .request
        .as_ref()
        .and_then(|request| request.correlation_id.as_deref());
    score += if present(correlation) { 10 } else { 0 };

    let recommended_present = policy
        .requirements
        .recommended_fields
        .iter()
        .filter(|path| has_value(candidate, path))
        .count();
    score += i64::try_from(recommended_present.min(5)).unwrap_or(5);
    // At most 40 + 30 + 30 + 5 = 105 before clamping.
    i32::try_from(score.min(100)).unwrap_or(100)
}
