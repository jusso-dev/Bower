//! Port of the policy parts of `SuppressionTests.cs` (loader, hash, set validation and
//! the evaluator's suppression directive).

mod common;

use bower_contracts::{DecisionAction, TelemetryPolicyEvaluator};
use bower_policy::{DeterministicPolicyEvaluator, load_yaml, validate_set};
use common::{authentication_failure, now};

pub const SUPPRESSING_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-AUTH-SUPPRESSED
  name: Authentication failures, suppressed
  version: 1.0.0
  owner: Security Operations
match:
  eventCategories:
    - authentication
  eventTypes:
    - authentication_failure
requirements:
  requiredFields:
    - timeGenerated
    - eventType
  atLeastOne:
    - actor.username
decision:
  action: accept
  minimumValueScore: 50
  neverSample: false
suppression:
  keyFields:
    - actor.username
    - source.ipAddress
  windowSeconds: 60
  allowPerWindow: 2";

pub const SUMMARY_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-SUPPRESSION-SUMMARY
  name: Suppression summaries
  version: 1.0.0
  owner: Security Operations
match:
  eventTypes:
    - telemetry_aggregation_summary
requirements:
  requiredFields:
    - timeGenerated
    - eventType
    - application.name
    - target.id
decision:
  action: accept
  minimumValueScore: 50
  neverSample: true";

#[test]
fn loader_rejects_invalid_suppression() {
    let cases = [
        (
            "neverSample: false",
            "neverSample: true",
            "A neverSample policy cannot define suppression.",
        ),
        (
            "action: accept",
            "action: reject",
            "Suppression applies only to accept or redact-and-accept policies.",
        ),
        (
            "    - source.ipAddress\n  windowSeconds",
            "    - attributes.password\n  windowSeconds",
            "Policy suppression keyFields must list 1–5 distinct string field paths.",
        ),
        (
            "    - source.ipAddress\n  windowSeconds",
            "    - actor.username\n  windowSeconds",
            "Policy suppression keyFields must list 1–5 distinct string field paths.",
        ),
        (
            "    - source.ipAddress\n  windowSeconds",
            "    - ~\n  windowSeconds",
            "Policy suppression keyFields must list 1–5 distinct string field paths.",
        ),
        (
            "windowSeconds: 60",
            "windowSeconds: 0",
            "Policy suppression windowSeconds must be between 1 and 86400.",
        ),
        (
            "allowPerWindow: 2",
            "allowPerWindow: 100001",
            "Policy suppression allowPerWindow must be between 1 and 100000.",
        ),
    ];
    for (original, replacement, message) in cases {
        let yaml = SUPPRESSING_POLICY.replace(original, replacement);
        assert_ne!(yaml, SUPPRESSING_POLICY);
        let error = load_yaml(&yaml, "suppressed.yaml").unwrap_err();
        assert_eq!(error.to_string(), message, "{replacement}");
    }
}

#[test]
fn hash_includes_suppression_only_when_present() {
    let suppressed = load_yaml(SUPPRESSING_POLICY, "suppressed.yaml").unwrap();
    let without = &SUPPRESSING_POLICY[..SUPPRESSING_POLICY.find("suppression:").unwrap()];
    let plain = load_yaml(without, "plain.yaml").unwrap();
    let other = load_yaml(
        &SUPPRESSING_POLICY.replace("windowSeconds: 60", "windowSeconds: 61"),
        "other.yaml",
    )
    .unwrap();

    assert!(plain.policy.suppression.is_none());
    assert_ne!(plain.hash, suppressed.hash);
    assert_ne!(suppressed.hash, other.hash);
    assert_eq!(
        suppressed.policy.suppression.as_ref().unwrap().key_fields,
        ["actor.username", "source.ipAddress"]
    );
}

#[test]
fn set_requires_a_policy_accepting_the_summary() {
    let suppressed = load_yaml(SUPPRESSING_POLICY, "suppressed.yaml").unwrap();
    let summary = load_yaml(SUMMARY_POLICY, "summary.yaml").unwrap();
    let rejecting = load_yaml(
        &SUMMARY_POLICY.replace("action: accept", "action: reject"),
        "summary.yaml",
    )
    .unwrap();

    assert_eq!(
        validate_set(std::slice::from_ref(&suppressed))
            .unwrap_err()
            .to_string(),
        "Policies define suppression but none accepts 'telemetry_aggregation_summary'."
    );
    assert!(validate_set(&[suppressed.clone(), rejecting]).is_err());
    assert!(validate_set(&[suppressed, summary.clone()]).is_ok());
    assert!(validate_set(&[summary]).is_ok());
    assert!(validate_set(&[]).is_ok());
}

#[test]
fn evaluator_attaches_directive_only_to_accepted_events() {
    let evaluator =
        DeterministicPolicyEvaluator::new([load_yaml(SUPPRESSING_POLICY, "s.yaml").unwrap()]);
    let mut event = authentication_failure(now());
    event.labels = None;

    let accepted = evaluator.evaluate(&event);
    let directive = accepted.suppression.expect("accepted events carry a key");
    assert_eq!(accepted.action, DecisionAction::Accept);
    assert_eq!(directive.key_fields, ["actor.username", "source.ipAddress"]);
    assert_eq!(directive.key_values, ["test-user", "192.0.2.10"]);
    assert_eq!(
        (directive.window_seconds, directive.allow_per_window),
        (60, 2)
    );

    // Missing username quarantines: no directive.
    event.actor = None;
    let quarantined = evaluator.evaluate(&event);
    assert_eq!(quarantined.action, DecisionAction::Quarantine);
    assert!(quarantined.suppression.is_none());
}

#[test]
fn absent_key_values_are_empty_and_labels_are_keys() {
    let yaml = SUPPRESSING_POLICY.replace(
        "    - source.ipAddress\n",
        "    - labels.tenant.region\n    - request.traceId\n",
    );
    let evaluator = DeterministicPolicyEvaluator::new([load_yaml(&yaml, "s.yaml").unwrap()]);
    let mut event = authentication_failure(now());
    event.labels = Some(
        [("tenant.region".to_owned(), "au-east".to_owned())]
            .into_iter()
            .collect(),
    );
    let directive = evaluator.evaluate(&event).suppression.unwrap();
    assert_eq!(directive.key_values, ["test-user", "au-east", ""]);
}
