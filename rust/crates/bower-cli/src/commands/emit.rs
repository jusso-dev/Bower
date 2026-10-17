//! `bower test emit [--endpoint URL]` (C# `EmitCanaryAsync`).

use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    ActorContext, ActorType, ApplicationContext, CURRENT_SCHEMA_VERSION, EventResult,
    EventSeverity, RequestContext, SecurityEventEnvelope, SourceContext,
};
use indexmap::IndexMap;

use crate::cli::EmitArgs;
use crate::support::{CliError, CliResult, ensure_slash};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:4319";

/// C# `test emit` uses a bare `HttpClient` (100 second default timeout).
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(100);

/// The synthetic authentication-failure canary C# `test emit` sends.
pub fn canary() -> SecurityEventEnvelope {
    let canary_id = format!("bower-canary-{}", uuid::Uuid::now_v7());
    SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: uuid::Uuid::now_v7().to_string(),
        event_original_id: Some(canary_id.clone()),
        time_generated: bower_contracts::time::now(),
        time_observed: None,
        event_category: event_categories::AUTHENTICATION.to_owned(),
        event_type: event_types::AUTHENTICATION_FAILURE.to_owned(),
        event_action: "authentication.attempt".to_owned(),
        event_result: EventResult::Failure,
        event_severity: EventSeverity::default(),
        event_outcome_reason: Some("SyntheticInvalidPassword".to_owned()),
        application: ApplicationContext {
            name: "BowerCanary".to_owned(),
            version: None,
            environment: "test".to_owned(),
            instance: Some(machine_name()),
            tenant_id: None,
        },
        actor: Some(ActorContext {
            username: Some("synthetic-canary".to_owned()),
            actor_type: ActorType::System,
            ..ActorContext::default()
        }),
        target: None,
        source: Some(SourceContext {
            ip_address: Some("192.0.2.1".to_owned()),
            ..SourceContext::default()
        }),
        request: Some(RequestContext {
            correlation_id: Some(canary_id),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: None,
        labels: Some(IndexMap::from([(
            "evidenceType".to_owned(),
            "test".to_owned(),
        )])),
        attributes: None,
        privacy: None,
    }
}

/// `Environment.MachineName`: host name up to the first dot.
pub fn machine_name() -> String {
    let from_env = ["COMPUTERNAME", "HOSTNAME"].iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    });
    let raw = from_env
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        })
        .unwrap_or_else(|| "localhost".to_owned());
    let trimmed = raw.trim();
    trimmed.split('.').next().unwrap_or(trimmed).to_owned()
}

pub fn run(args: &EmitArgs) -> CliResult {
    let endpoint = args.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
    let base = reqwest::Url::parse(&ensure_slash(endpoint)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let url = base.join("v1/events").map_err(CliError::from_display)?;
    let body = bower_contracts::json::to_vec(&canary()).map_err(CliError::from_display)?;
    let token = std::env::var("BOWER_INGEST_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    super::block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(CliError::from_display)?;
        let mut request = client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| super::http_error(&error, HTTP_TIMEOUT))?;
        let success = response.status().is_success();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| super::http_error(&error, HTTP_TIMEOUT))?;
        println!("{}", String::from_utf8_lossy(&bytes));
        Ok(if success { 0 } else { 2 })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_serializes_with_bower_json() {
        let text = bower_contracts::json::to_string(&canary()).unwrap();
        assert!(text.contains("\"eventType\":\"authentication_failure\""));
        assert!(text.contains("\"labels\":{\"evidenceType\":\"test\"}"));
        assert!(text.contains("\"actor\":{\"username\":\"synthetic-canary\",\"type\":\"system\"}"));
        assert!(text.contains("\"eventOriginalId\":\"bower-canary-"));
    }
}
