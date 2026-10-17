//! `SecurityEventEnvelope` and nested contexts (schema `1.0.0`).

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::element::JsonElement;
use crate::time::{Timestamp, serde_offset, serde_offset_option};

pub const CURRENT_SCHEMA_VERSION: &str = "1.0.0";

/// String enums serialized camelCase and read by member name (any case) or by the
/// ordinal of a declared member, matching C# `DefinedEnumConverter`. Undefined
/// ordinals, numeric strings and comma-joined names are rejected (default deny).
macro_rules! dotnet_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $camel:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name { $($(#[$vmeta])* $variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// camelCase JSON name.
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $camel),+ }
            }

            /// PascalCase name, as returned by C# `Enum.ToString()`.
            pub fn pascal_name(self) -> &'static str {
                match self { $($name::$variant => stringify!($variant)),+ }
            }

            pub fn parse_name(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.as_str().eq_ignore_ascii_case(text))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.pascal_name())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                match Value::deserialize(deserializer)? {
                    Value::String(text) => Self::parse_name(&text).ok_or_else(|| {
                        serde::de::Error::custom(format!("unknown {} value", stringify!($name)))
                    }),
                    Value::Number(number) => number
                        .as_u64()
                        .and_then(|index| Self::ALL.get(usize::try_from(index).ok()?).copied())
                        .ok_or_else(|| serde::de::Error::custom(format!("unknown {} ordinal", stringify!($name)))),
                    _ => Err(serde::de::Error::custom(format!("{} must be a string", stringify!($name)))),
                }
            }
        }
    };
}

dotnet_enum!(EventResult { #[default] Unknown => "unknown", Success => "success", Failure => "failure", Denied => "denied" });

dotnet_enum!(EventSeverity {
    Informational => "informational",
    Low => "low",
    #[default]
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

dotnet_enum!(ActorType {
    #[default]
    Human => "human",
    Service => "service",
    Machine => "machine",
    System => "system",
    Unknown => "unknown",
});

dotnet_enum!(DecisionAction {
    #[default]
    Accept => "accept",
    Reject => "reject",
    Sample => "sample",
    Aggregate => "aggregate",
    RedactAndAccept => "redactAndAccept",
    Quarantine => "quarantine",
    DeadLetter => "deadLetter",
});

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventEnvelope {
    pub schema_version: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_original_id: Option<String>,
    #[serde(with = "serde_offset")]
    pub time_generated: Timestamp,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_offset_option"
    )]
    pub time_observed: Option<Timestamp>,
    pub event_category: String,
    pub event_type: String,
    pub event_action: String,
    pub event_result: EventResult,
    #[serde(default)]
    pub event_severity: EventSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_outcome_reason: Option<String>,
    /// Required, but `null` reads as an empty context (see [`application_or_null`]).
    #[serde(deserialize_with = "application_or_null")]
    pub application: ApplicationContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<ChangeContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityDecisionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<CollectorContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<IndexMap<String, JsonElement>>,
    /// Sanitisation summary from the privacy engine. Never contains original values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<PrivacyContext>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyContext {
    pub detected: Vec<String>,
    pub actions: IndexMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationContext {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// `System.Text.Json` binds `"application": null` (`required` only checks presence), so
/// the C# processor sees a null application and quarantines the event with the
/// validation reason instead of rejecting the JSON. An empty context reproduces that:
/// validation fails with the same reason, and a privacy alert built from the event
/// carries the same empty application C# substitutes for null. A missing property or a
/// context without `name`/`environment` is still invalid JSON.
fn application_or_null<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ApplicationContext, D::Error> {
    Ok(
        Option::<ApplicationContext>::deserialize(deserializer)?.unwrap_or_else(|| {
            ApplicationContext {
                name: String::new(),
                version: None,
                environment: String::new(),
                instance: None,
                tenant_id: None,
            }
        }),
    )
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActorContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, rename = "type")]
    pub actor_type: ActorType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetContext {
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityDecisionContext {
    pub policy_id: String,
    pub policy_version: String,
    pub value_score: i32,
    pub decision: DecisionAction,
    pub classification_reasons: Vec<String>,
    pub policy_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorContext {
    pub id: String,
    pub version: String,
    pub source_adapter: String,
    pub configuration_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(with = "serde_offset")]
    pub received_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    const SAMPLE: &str = r#"{"schemaVersion":"1.0.0","eventId":"e1","timeGenerated":"2026-05-01T10:20:30Z","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"login","eventResult":"Failure","application":{"name":"app","environment":"prod"},"actor":{"userId":"u1"},"attributes":{"b":1.50,"a":[true,null]}}"#;

    #[test]
    fn round_trips_with_dotnet_shape() {
        let envelope: SecurityEventEnvelope = json::from_str(SAMPLE).unwrap();
        assert_eq!(envelope.event_result, EventResult::Failure);
        assert_eq!(envelope.event_severity, EventSeverity::Medium);
        assert_eq!(
            json::to_string(&envelope).unwrap(),
            r#"{"schemaVersion":"1.0.0","eventId":"e1","timeGenerated":"2026-05-01T10:20:30+00:00","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"login","eventResult":"failure","eventSeverity":"medium","application":{"name":"app","environment":"prod"},"actor":{"userId":"u1","type":"human"},"attributes":{"b":1.50,"a":[true,null]}}"#
        );
    }

    #[test]
    fn undefined_enum_values_are_rejected_like_csharp() {
        // C# `DefinedEnumConverter`: declared names and ordinals only (default deny).
        for text in [
            "7",
            "-1",
            "4",
            "1.5",
            "\"7\"",
            "\"2\"",
            "\"success, failure\"",
            "\"bogus\"",
            "null",
            "true",
        ] {
            assert!(serde_json::from_str::<EventResult>(text).is_err(), "{text}");
        }
        assert!(serde_json::from_str::<EventSeverity>("5").is_err());
        assert!(serde_json::from_str::<ActorType>("5").is_err());
        assert!(serde_json::from_str::<DecisionAction>("7").is_err());
        assert_eq!(
            serde_json::from_str::<EventResult>("3").unwrap(),
            EventResult::Denied
        );
        assert_eq!(
            serde_json::from_str::<EventSeverity>("4").unwrap(),
            EventSeverity::Critical
        );
        assert_eq!(
            serde_json::from_str::<ActorType>("4").unwrap(),
            ActorType::Unknown
        );
        assert_eq!(
            serde_json::from_str::<DecisionAction>("\"DEADLETTER\"").unwrap(),
            DecisionAction::DeadLetter
        );
        let envelope = SAMPLE.replace(r#""eventResult":"Failure""#, r#""eventResult":7"#);
        assert!(json::from_str::<SecurityEventEnvelope>(&envelope).is_err());
    }

    #[test]
    fn null_application_binds_as_empty_context_like_csharp() {
        let envelope: SecurityEventEnvelope = json::from_str(&SAMPLE.replace(
            r#""application":{"name":"app","environment":"prod"}"#,
            r#""application":null"#,
        ))
        .unwrap();
        assert_eq!(envelope.application.name, "");
        assert_eq!(envelope.application.environment, "");
        assert_eq!(envelope.application.tenant_id, None);
        assert!(
            json::to_string(&envelope)
                .unwrap()
                .contains(r#""application":{"name":"","environment":""}"#)
        );

        // Still required, and a present context still needs its required members.
        for replacement in [
            "",
            r#""application":{},"#,
            r#""application":{"name":"app"},"#,
        ] {
            let text = SAMPLE.replace(
                r#""application":{"name":"app","environment":"prod"},"#,
                replacement,
            );
            assert!(
                json::from_str::<SecurityEventEnvelope>(&text).is_err(),
                "{replacement}"
            );
        }
    }

    #[test]
    fn enums_accept_ordinals_and_render_pascal_names() {
        let value: DecisionAction = serde_json::from_str("4").unwrap();
        assert_eq!(value, DecisionAction::RedactAndAccept);
        assert_eq!(value.to_string(), "RedactAndAccept");
        assert_eq!(json::to_string(&value).unwrap(), "\"redactAndAccept\"");
    }
}
