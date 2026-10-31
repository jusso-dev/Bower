//! Well-known event type and category identifiers.

pub mod event_types {
    pub const AUTHENTICATION_FAILURE: &str = "authentication_failure";
    pub const AUTHENTICATION_SUCCESS: &str = "authentication_success";
    pub const ACCOUNT_LOCKOUT: &str = "account_lockout";
    pub const ROLE_MEMBERSHIP_CHANGED: &str = "role_membership_changed";
    pub const SENSITIVE_DATA_EXPORTED: &str = "sensitive_data_exported";
    /// Privacy engine detected sensitive material and applied a control action.
    /// Never carries original secret values — detector ids and actions only.
    pub const SENSITIVE_DATA_DETECTED: &str = "sensitive_data_detected";
    pub const COLLECTOR_STARTED: &str = "collector_started";
    /// Synthetic event sent by `bower evidence run`; always labelled evidenceType=canary.
    pub const COLLECTOR_CANARY: &str = "collector_canary";
    pub const COLLECTOR_UPLOAD_FAILED: &str = "collector_upload_failed";
    /// Periodic collector health record. Emitted only by the C# collector; the Rust
    /// collector refuses BOWER_HEALTH_RECORD_INTERVAL_SECONDS.
    pub const COLLECTOR_HEALTH: &str = "collector_health";
    pub const TELEMETRY_AGGREGATION_SUMMARY: &str = "telemetry_aggregation_summary";
}

pub mod event_categories {
    pub const AUTHENTICATION: &str = "authentication";
    pub const AUTHORISATION: &str = "authorisation";
    pub const IDENTITY_MANAGEMENT: &str = "identity-management";
    pub const ADMINISTRATIVE_ACTIVITY: &str = "administrative-activity";
    pub const DATA_ACCESS: &str = "data-access";
    pub const APPLICATION_SECURITY: &str = "application-security";
    pub const API_SECURITY: &str = "api-security";
    pub const COLLECTOR_HEALTH: &str = "collector-health";
    /// Privacy controls, DLP-style findings, data minimisation actions.
    pub const PRIVACY_CONTROL: &str = "privacy-control";
}
