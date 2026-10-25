//! Port of `TelemetryPolicy.cs` and `LoadedPolicy`.
//!
//! These are the validated, non-null views of a policy. Loading keeps a
//! separate nullable model (see `loader`) so the policy hash covers exactly the
//! values YamlDotNet would have produced, including explicit YAML nulls.

use chrono::NaiveDate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetryPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    pub r#match: PolicyMatch,
    pub requirements: PolicyRequirements,
    pub decision: PolicyAction,
    pub routing: Option<PolicyRouting>,
    /// Optional per-key cap on accepted events; omitted from the hash when absent.
    pub suppression: Option<PolicySuppression>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub owner: String,
    pub review_date: Option<NaiveDate>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyMatch {
    pub event_categories: Vec<String>,
    pub event_types: Vec<String>,
    pub event_actions: Option<Vec<String>>,
    pub event_results: Option<Vec<String>>,
    pub event_severities: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRequirements {
    pub required_fields: Vec<String>,
    pub at_least_one: Vec<String>,
    pub recommended_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyAction {
    pub action: String,
    pub minimum_value_score: i32,
    pub never_sample: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRouting {
    pub profile: Option<String>,
    pub destination: Option<String>,
}

/// Admits at most `allow_per_window` accepted events per key in each fixed,
/// epoch-aligned window of `window_seconds`. Later events are counted durably and
/// reported by one `telemetry_aggregation_summary` event when the window ends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySuppression {
    pub key_fields: Vec<String>,
    pub window_seconds: i32,
    pub allow_per_window: i32,
}

/// A validated policy with its content hash (`sha256:<hex>`) and source name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPolicy {
    pub policy: TelemetryPolicy,
    pub hash: String,
    pub source_path: String,
}
