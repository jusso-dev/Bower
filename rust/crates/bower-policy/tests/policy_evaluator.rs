//! Port of `PolicyEvaluatorTests.cs`, plus a decision corpus produced by the
//! C# `DeterministicPolicyEvaluator` (git HEAD bf15994) over
//! `policies/default` and `tests/fixtures/eval/policies`.

mod common;

use bower_contracts::{DecisionAction, SecurityEventEnvelope, TelemetryPolicyEvaluator, json};
use bower_policy::{DeterministicPolicyEvaluator, LoadedPolicy, PolicyMatch, load_directory};
use common::{authentication_failure, authentication_policy, fixtures_dir, now};

#[test]
fn evaluate_accepts_complete_approved_event_with_explanation() {
    let evaluator = DeterministicPolicyEvaluator::new([authentication_policy()]);

    let result = evaluator.evaluate(&authentication_failure(now()));

    assert_eq!(result.action, DecisionAction::Accept);
    assert_eq!(result.policy_id, "BWR-POL-AUTH-FAILURE");
    assert!(result.score >= 70);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("meets minimum"))
    );
}

#[test]
fn evaluate_default_denies_unknown_event() {
    let evaluator = DeterministicPolicyEvaluator::new([authentication_policy()]);
    let unknown = SecurityEventEnvelope {
        event_type: "free_form_diagnostic".to_owned(),
        event_category: "diagnostic".to_owned(),
        ..authentication_failure(now())
    };

    let result = evaluator.evaluate(&unknown);

    assert_eq!(result.action, DecisionAction::Reject);
    assert_eq!(result.policy_id, "BWR-POL-DEFAULT-DENY");
    assert_eq!(result.policy_version, "1.0.0");
    assert_eq!(result.policy_hash, "builtin:default-deny-v1");
    assert_eq!(result.score, 0);
    assert_eq!(
        result.reasons,
        ["No approved policy matched event category and type"]
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn evaluate_quarantines_event_missing_actor() {
    let evaluator = DeterministicPolicyEvaluator::new([authentication_policy()]);
    let incomplete = SecurityEventEnvelope {
        actor: None,
        ..authentication_failure(now())
    };

    let result = evaluator.evaluate(&incomplete);

    assert_eq!(result.action, DecisionAction::Quarantine);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.starts_with("Missing required field"))
    );
    // Exact C# values: 40 + 15 (one missing) + 5 source + 10 correlation + 3 recommended.
    assert_eq!(result.score, 73);
    assert_eq!(
        result.reasons,
        ["Missing required field: one-of(actor.userId,actor.username)"]
    );
}

/// From `PolicyLoaderTests.Evaluator_DeniesUnknownTypeEvenForCategoryOnlyPolicy`.
#[test]
fn evaluator_denies_unknown_type_even_for_category_only_policy() {
    let mut category_only = authentication_policy();
    category_only.policy.r#match = PolicyMatch {
        event_categories: vec!["authentication".to_owned()],
        event_types: Vec::new(),
    };
    let evaluator = DeterministicPolicyEvaluator::new([category_only]);

    let decision = evaluator.evaluate(&SecurityEventEnvelope {
        event_type: "brand_new_type".to_owned(),
        ..authentication_failure(now())
    });

    assert_eq!(decision.action, DecisionAction::Reject);
    assert_eq!(decision.policy_id, "BWR-POL-DEFAULT-DENY");
}

#[test]
fn first_matching_policy_by_ordinal_id_wins_regardless_of_input_order() {
    let mut later = authentication_policy();
    later.policy.metadata.id = "b".to_owned();
    later.policy.decision.action = "sample".to_owned();
    let mut earlier = authentication_policy();
    earlier.policy.metadata.id = "B".to_owned();

    for policies in [
        vec![later.clone(), earlier.clone()],
        vec![earlier.clone(), later.clone()],
    ] {
        let evaluator = DeterministicPolicyEvaluator::new(policies);
        let decision = evaluator.evaluate(&authentication_failure(now()));
        assert_eq!(decision.policy_id, "B");
        assert_eq!(decision.action, DecisionAction::Accept);
    }
}

fn all_policies() -> Vec<LoadedPolicy> {
    let mut policies = load_directory(common::default_policies_dir()).unwrap();
    policies.extend(load_directory(fixtures_dir().join("eval/policies")).unwrap());
    policies
}

/// Decisions, scores, reasons and warnings match the C# evaluator exactly.
#[test]
fn decisions_match_csharp_corpus() {
    let evaluator = DeterministicPolicyEvaluator::new(all_policies());
    let events = std::fs::read_to_string(fixtures_dir().join("eval/events.jsonl")).unwrap();
    let expected = std::fs::read_to_string(fixtures_dir().join("eval/expected.tsv")).unwrap();

    let events: Vec<&str> = events
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let expected: Vec<&str> = expected.lines().collect();
    assert_eq!(events.len(), expected.len());
    assert!(events.len() >= 30);

    for (line, expected) in events.iter().zip(expected) {
        let envelope: SecurityEventEnvelope = json::from_str(line).unwrap();
        let decision = evaluator.evaluate(&envelope);
        let actual = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            decision.action,
            decision.policy_id,
            decision.policy_version,
            decision.policy_hash,
            decision.score,
            decision.reasons.join("|"),
            decision.warnings.join("|"),
        );
        assert_eq!(actual, expected, "event {line}");
    }
}
