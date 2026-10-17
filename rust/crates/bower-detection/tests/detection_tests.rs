//! Ports of `DetectionEngineTests` plus loader parity against `SigmaRuleLoader`
//! output captured from C#.

use std::path::PathBuf;

use bower_contracts::{
    ActorContext, ApplicationContext, CURRENT_SCHEMA_VERSION, EventResult, EventSeverity,
    SecurityEventEnvelope, SourceContext,
};
use bower_detection::{DetectionEngine, DetectionRule, load_directory, load_file, load_yaml};
use indexmap::IndexMap;
use serde_json::json;

fn repo(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn rule_json(rule: &DetectionRule) -> String {
    let fields: serde_json::Map<String, serde_json::Value> = rule
        .detection_fields
        .iter()
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect();
    bower_contracts::json::to_string(&json!({
        "Id": rule.id,
        "Title": rule.title,
        "Version": rule.version,
        "Level": rule.level,
        "Status": rule.status,
        "Description": rule.description,
        "LogSources": rule.log_sources,
        "DetectionFields": fields,
        "Condition": rule.condition,
        "MitreTechniques": rule.mitre_techniques,
        "FalsePositiveHints": rule.false_positive_hints,
        "RuleHash": rule.rule_hash,
    }))
    .unwrap()
}

#[test]
fn loader_matches_csharp_for_every_shipped_rule() {
    let files = [
        "packs/aws-security/detections/aws-access-key-created.yml",
        "packs/aws-security/detections/aws-console-login-failure.yml",
        "packs/aws-security/detections/aws-logging-tampering.yml",
        "packs/aws-security/detections/aws-root-activity.yml",
        "packs/gcp-security/detections/gcp-iam-policy-changed.yml",
        "packs/gcp-security/detections/gcp-logging-tampering.yml",
        "packs/gcp-security/detections/gcp-permission-denied.yml",
        "packs/gcp-security/detections/gcp-service-account-key-created.yml",
        "packs/linux-ssh-gateway/detections/ssh-password-spray.yml",
        "rules/sigma/auth_failure_burst.yml",
    ];
    let expected = std::fs::read_to_string(fixture("sigma.jsonl")).unwrap();
    let mut actual: Vec<String> = files
        .iter()
        .map(|file| rule_json(&load_file(&repo(file)).unwrap()))
        .collect();
    actual.push(rule_json(&load_file(&fixture("odd.yml")).unwrap()));

    assert_eq!(actual, expected.lines().collect::<Vec<_>>());
}

#[test]
fn load_directory_parses_sample_sigma_rule() {
    let rules = load_directory(&repo("rules/sigma")).unwrap();

    let auth = rules
        .iter()
        .find(|rule| rule.id == "bower-auth-failure-001")
        .unwrap();
    assert!(auth.mitre_techniques.contains(&"T1110".to_owned()));
    assert_eq!(auth.level, "medium");
}

#[test]
fn loader_rejects_malformed_rules() {
    assert!(load_yaml("   ", None).is_err());
    assert!(load_yaml("- a\n- b\n", None).is_err());
    assert!(load_yaml("title: t\ndetection:\n  selection:\n    a: b\n", None).is_err());
    let no_selection = load_yaml("title: t\nid: x\n", None).unwrap_err();
    assert_eq!(
        no_selection.to_string(),
        "Sigma rule 'x' has no detection selections."
    );
    let missing = load_yaml("id: x\n", Some("r.yml")).unwrap_err();
    assert_eq!(
        missing.to_string(),
        "Sigma rule 'r.yml' missing required field 'title'."
    );
    assert!(
        load_yaml(
            &format!("title: t\nid: x\ndescription: {}", "x".repeat(256 * 1024)),
            None
        )
        .is_err()
    );
}

fn envelope(event_type: &str) -> SecurityEventEnvelope {
    SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: uuid::Uuid::now_v7().to_string(),
        event_original_id: None,
        time_generated: bower_contracts::time::now(),
        time_observed: None,
        event_category: "authentication".to_owned(),
        event_type: event_type.to_owned(),
        event_action: "authentication.attempt".to_owned(),
        event_result: EventResult::Failure,
        event_severity: EventSeverity::Medium,
        event_outcome_reason: None,
        application: ApplicationContext {
            name: "app".to_owned(),
            version: None,
            environment: "test".to_owned(),
            instance: None,
            tenant_id: None,
        },
        actor: None,
        target: None,
        source: None,
        request: None,
        change: None,
        security: None,
        collector: None,
        labels: None,
        attributes: None,
        privacy: None,
    }
}

#[test]
fn evaluate_raises_alert_for_authentication_failure() {
    let rule = load_yaml(
        "title: Auth Fail\nid: test-auth-1\nlevel: high\nversion: 1.0.0\ndetection:\n  selection:\n    EventType: authentication_failure\n  condition: selection\ntags:\n  - attack.t1110\n",
        None,
    )
    .unwrap();
    let mut engine = DetectionEngine::new(vec![rule], Vec::new());
    let mut event = envelope("authentication_failure");
    event.actor = Some(ActorContext {
        username: Some("alice".to_owned()),
        ..ActorContext::default()
    });
    event.source = Some(SourceContext {
        ip_address: Some("203.0.113.9".to_owned()),
        ..SourceContext::default()
    });

    let result = engine.evaluate(&event, None);

    assert_eq!(result.alerts.len(), 1);
    let alert = &result.alerts[0];
    assert_eq!(alert.rule_id, "test-auth-1");
    assert_eq!(alert.risk_score, 75);
    assert!(alert.mitre_techniques.contains(&"T1110".to_owned()));
    assert_eq!(alert.actor.as_deref(), Some("alice"));
    assert_eq!(alert.source_ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(alert.matched_fields, ["EventType"]);

    // The same event never alerts twice for the same rule version.
    assert!(engine.evaluate(&event, None).alerts.is_empty());
}

#[test]
fn evaluate_suppresses_configured_rule_ids() {
    let rule = load_yaml(
        "title: Auth Fail\nid: suppressed-1\nlevel: low\ndetection:\n  selection:\n    EventType: authentication_failure\n  condition: selection\n",
        None,
    )
    .unwrap();
    let mut engine = DetectionEngine::new(vec![rule], vec!["SUPPRESSED-1".to_owned()]);

    let result = engine.evaluate(&envelope("authentication_failure"), None);

    assert!(result.alerts.is_empty());
    assert_eq!(result.suppressed_rule_ids, ["suppressed-1"]);
}

#[test]
fn pack_detections_fire_on_matching_labels_and_aliases() {
    let rules: Vec<DetectionRule> = ["aws-root-activity", "aws-console-login-failure"]
        .iter()
        .map(|name| load_file(&repo(&format!("packs/aws-security/detections/{name}.yml"))).unwrap())
        .collect();
    let mut engine = DetectionEngine::new(rules, Vec::new());
    let mut event = envelope("aws_cloudtrail");
    event.event_action = "ConsoleLogin".to_owned();
    let mut labels = IndexMap::new();
    labels.insert("aws.identityType".to_owned(), "Root".to_owned());
    event.labels = Some(labels);

    let mut fired: Vec<String> = engine
        .evaluate(&event, None)
        .alerts
        .into_iter()
        .map(|alert| alert.rule_id)
        .collect();
    fired.sort();
    assert_eq!(
        fired,
        [
            "bower-pack-aws-console-login-failure-001",
            "bower-pack-aws-root-activity-001"
        ]
    );

    let mut engine = DetectionEngine::new(
        vec![
            load_yaml(
                "title: t\nid: alias\ndetection:\n  selection:\n    identityType: root\n",
                None,
            )
            .unwrap(),
        ],
        Vec::new(),
    );
    assert_eq!(
        engine.evaluate(&event, None).alerts.len(),
        1,
        "falls back to a key ending with the field name"
    );
}

#[test]
fn any_group_conditions_and_payload_clauses() {
    let rule = load_yaml(
        "title: t\nid: or-1\ndetection:\n  first:\n    EventType: nope\n  second:\n    - FAILURE\n  condition: first or second\n",
        None,
    )
    .unwrap();
    let mut engine = DetectionEngine::new(vec![rule], Vec::new());
    let result = engine.evaluate(&envelope("authentication_failure"), None);
    assert_eq!(result.alerts.len(), 1);
    assert_eq!(result.alerts[0].matched_fields, ["payload"]);

    let json = bower_contracts::json::to_string(&envelope("authentication_failure")).unwrap();
    let mut engine = DetectionEngine::new(
        vec![
            load_yaml(
                "title: t\nid: j\ndetection:\n  selection:\n    EventCategory: auth\n",
                None,
            )
            .unwrap(),
        ],
        Vec::new(),
    );
    assert_eq!(engine.evaluate_json(&json, None).unwrap().alerts.len(), 1);
    assert!(engine.evaluate_json("{}", None).is_err());
}

/// `fixtures/csharp-alerts.txt` was written by C# `DetectionEngine.EvaluateJson` (temporary
/// xunit emitter): every shipped rule, one engine, over every pack sample event (with
/// `{{now}}` fixed) and every C#-mapped cloud envelope in the bower-packs fixtures,
/// `bower-pack-gcp-logging-tampering-001` suppressed. Alert ids are random in both
/// implementations and are not compared.
#[test]
fn alerts_match_csharp_for_pack_samples_and_mapped_cloud_events() {
    let files = [
        "packs/aws-security/detections/aws-access-key-created.yml",
        "packs/aws-security/detections/aws-console-login-failure.yml",
        "packs/aws-security/detections/aws-logging-tampering.yml",
        "packs/aws-security/detections/aws-root-activity.yml",
        "packs/gcp-security/detections/gcp-iam-policy-changed.yml",
        "packs/gcp-security/detections/gcp-logging-tampering.yml",
        "packs/gcp-security/detections/gcp-permission-denied.yml",
        "packs/gcp-security/detections/gcp-service-account-key-created.yml",
        "packs/linux-ssh-gateway/detections/ssh-password-spray.yml",
        "rules/sigma/auth_failure_burst.yml",
    ];
    let rules: Vec<DetectionRule> = files
        .iter()
        .map(|file| load_file(&repo(file)).unwrap())
        .collect();
    let mut engine = DetectionEngine::new(
        rules,
        vec!["bower-pack-gcp-logging-tampering-001".to_owned()],
    );
    let detected_at = bower_contracts::time::parse("2026-10-17T01:02:03.4567+00:00").unwrap();

    let mut events: Vec<(String, String)> = Vec::new();
    for id in ["linux-ssh-gateway", "aws-security", "gcp-security"] {
        let mut samples: Vec<PathBuf> = std::fs::read_dir(repo(&format!("packs/{id}/samples")))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect();
        samples.sort();
        for sample in samples {
            let text = std::fs::read_to_string(sample).unwrap();
            for (index, line) in text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                let event = value["event"]
                    .to_string()
                    .replace("{{now}}", "2026-10-17T01:00:00Z");
                events.push((format!("{id}:{}", index + 1), event));
            }
        }
    }
    let envelopes = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../bower-packs/tests/fixtures/csharp-vectors");
    let mut names: Vec<String> = std::fs::read_dir(&envelopes)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("envelope-") && name.ends_with(".json"))
        .collect();
    names.sort();
    for name in names {
        let json = std::fs::read_to_string(envelopes.join(&name)).unwrap();
        events.push((name, json));
    }

    let mut actual = Vec::new();
    for (name, json) in &events {
        let result = engine.evaluate_json(json, Some(detected_at)).unwrap();
        for alert in result.alerts {
            actual.push(
                [
                    "alert".to_owned(),
                    name.clone(),
                    alert.rule_id,
                    alert.rule_title,
                    alert.rule_version,
                    alert.rule_hash,
                    alert.level,
                    alert.risk_score.to_string(),
                    bower_contracts::time::format_round_trip(&alert.detected_at),
                    alert.event_id,
                    alert.event_type.unwrap_or_else(|| "<null>".to_owned()),
                    alert.actor.unwrap_or_else(|| "<null>".to_owned()),
                    alert.source_ip.unwrap_or_else(|| "<null>".to_owned()),
                    alert.mitre_techniques.join(","),
                    alert.matched_fields.join(","),
                    alert.summary,
                ]
                .join("|"),
            );
        }
        actual.push(format!(
            "suppressed|{name}|{}",
            result.suppressed_rule_ids.join(",")
        ));
    }
    let repeats: usize = events
        .iter()
        .map(|(_, json)| {
            engine
                .evaluate_json(json, Some(detected_at))
                .unwrap()
                .alerts
                .len()
        })
        .sum();
    actual.push(format!("repeat-alerts|{repeats}"));

    let expected = std::fs::read_to_string(fixture("csharp-alerts.txt")).unwrap();
    assert_eq!(actual, expected.lines().collect::<Vec<_>>());
    assert_eq!(
        actual
            .iter()
            .filter(|line| line.starts_with("alert|"))
            .count(),
        18
    );
}
