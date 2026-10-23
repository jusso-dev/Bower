//! Port of the `TestEvents` helpers in `tests/Bower.UnitTests/TestSupport.cs`.

#![allow(dead_code)]

use std::path::PathBuf;

use bower_contracts::time::Timestamp;
use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    ActorContext, ApplicationContext, CURRENT_SCHEMA_VERSION, EventResult, EventSeverity,
    RequestContext, SecurityEventEnvelope, SourceContext,
};
use bower_policy::{
    LoadedPolicy, PolicyAction, PolicyMatch, PolicyMetadata, PolicyRequirements, TelemetryPolicy,
};
use chrono::DateTime;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn default_policies_dir() -> PathBuf {
    repo_root().join("policies/default")
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// 2026-07-26T02:14:19Z.
pub fn now() -> Timestamp {
    DateTime::parse_from_rfc3339("2026-07-26T02:14:19+00:00").unwrap()
}

pub fn authentication_failure(now: Timestamp) -> SecurityEventEnvelope {
    SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: "event-1".to_owned(),
        event_original_id: Some("source-1".to_owned()),
        time_generated: now,
        time_observed: None,
        event_category: event_categories::AUTHENTICATION.to_owned(),
        event_type: event_types::AUTHENTICATION_FAILURE.to_owned(),
        event_action: "authentication.attempt".to_owned(),
        event_result: EventResult::Failure,
        event_severity: EventSeverity::default(),
        event_outcome_reason: Some("InvalidPassword".to_owned()),
        application: ApplicationContext {
            name: "TestApplication".to_owned(),
            version: None,
            environment: "test".to_owned(),
            instance: None,
            tenant_id: None,
        },
        actor: Some(ActorContext {
            username: Some("test-user".to_owned()),
            ..ActorContext::default()
        }),
        target: None,
        source: Some(SourceContext {
            ip_address: Some("192.0.2.10".to_owned()),
            ..SourceContext::default()
        }),
        request: Some(RequestContext {
            correlation_id: Some("correlation-1".to_owned()),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: None,
        labels: None,
        attributes: None,
        privacy: None,
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

pub fn authentication_policy() -> LoadedPolicy {
    LoadedPolicy {
        policy: TelemetryPolicy {
            api_version: "bower.security/v1".to_owned(),
            kind: "TelemetryPolicy".to_owned(),
            metadata: PolicyMetadata {
                id: "BWR-POL-AUTH-FAILURE".to_owned(),
                name: "Authentication failures".to_owned(),
                version: "1.0.0".to_owned(),
                owner: "Security Operations".to_owned(),
                review_date: None,
            },
            r#match: PolicyMatch {
                event_categories: strings(&[event_categories::AUTHENTICATION]),
                event_types: strings(&[event_types::AUTHENTICATION_FAILURE]),
                ..Default::default()
            },
            requirements: PolicyRequirements {
                required_fields: strings(&[
                    "timeGenerated",
                    "eventType",
                    "eventResult",
                    "application.name",
                ]),
                at_least_one: strings(&["actor.userId", "actor.username"]),
                recommended_fields: strings(&[
                    "source.ipAddress",
                    "eventOutcomeReason",
                    "request.correlationId",
                ]),
            },
            decision: PolicyAction {
                action: "accept".to_owned(),
                minimum_value_score: 70,
                never_sample: true,
            },
            routing: None,
        },
        hash: "sha256:test-policy".to_owned(),
        source_path: "test".to_owned(),
    }
}
