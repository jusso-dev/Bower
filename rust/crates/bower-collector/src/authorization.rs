//! Exact producer identity tuples (C# ProducerAuthorization). Restart to change scopes.
use std::collections::HashSet;
use std::path::Path;

use bower_contracts::JsonElement;

use crate::HostError;

#[derive(PartialEq)]
struct Identity {
    name: String,
    environment: String,
    tenant_id: Option<String>,
    instance: Option<String>,
    hostname: Option<String>,
    ip_address: Option<String>,
    port: Option<i32>,
}

#[derive(Default)]
pub struct ProducerAuthorization {
    scopes: Vec<(String, Identity)>,
    single_trust_domain: bool,
}

impl ProducerAuthorization {
    pub fn new(path: Option<&Path>, single_trust_domain: bool) -> Result<Self, HostError> {
        let mut result = Self {
            scopes: Vec::new(),
            single_trust_domain,
        };
        let Some(path) = path else {
            return Ok(result);
        };
        if single_trust_domain {
            return Err(HostError::new(
                "InvalidOperationException",
                "Producer scopes and single trust domain mode are mutually exclusive.",
            ));
        }
        let text = std::fs::read_to_string(path).map_err(|error| HostError::io(path, &error))?;
        let invalid = || HostError::new("FormatException", "Invalid producer scopes file.");
        if text.len() > 1_048_576 {
            return Err(invalid());
        }
        let root =
            JsonElement::parse(text.trim_start_matches('\u{feff}')).map_err(|_| invalid())?;
        let JsonElement::Array(items) = root else {
            return Err(invalid());
        };
        if items.len() > 4096 {
            return Err(invalid());
        }
        for item in items {
            check_object(&item, Some(&["producer", "application", "source"]))
                .ok_or_else(invalid)?;
            let producer = required_string(&item, "producer").ok_or_else(invalid)?;
            if producer.encode_utf16().count() > 64 || producer.chars().any(char::is_whitespace) {
                return Err(invalid());
            }
            let identity = read_identity(&item, true).ok_or_else(invalid)?;
            result.scopes.push((producer, identity));
        }
        Ok(result)
    }

    pub fn is_authorized(&self, producer: &str, candidate: &str) -> bool {
        if self.single_trust_domain {
            return true;
        }
        let Ok(root) = JsonElement::parse(candidate) else {
            return false;
        };
        let Some(identity) = read_identity(&root, false) else {
            return false;
        };
        self.scopes
            .iter()
            .any(|(owner, allowed)| owner == producer && *allowed == identity)
    }
}

fn read_identity(root: &JsonElement, configuration: bool) -> Option<Identity> {
    check_object(root, None)?;
    let application = root.get("application")?;
    check_object(
        application,
        configuration.then_some(&["name", "environment", "tenantId", "instance"][..]),
    )?;
    let source = root.get("source").unwrap_or(&JsonElement::Null);
    if !matches!(source, JsonElement::Null) {
        check_object(
            source,
            configuration.then_some(&["hostname", "ipAddress", "port"][..]),
        )?;
    }
    let port = match source.get("port") {
        None | Some(JsonElement::Null) => None,
        Some(JsonElement::Number(value)) => Some(value.parse::<i32>().ok()?),
        _ => return None,
    };
    Some(Identity {
        name: required_string(application, "name")?,
        environment: required_string(application, "environment")?,
        tenant_id: optional_string(application, "tenantId")?,
        instance: optional_string(application, "instance")?,
        hostname: optional_string(source, "hostname")?,
        ip_address: optional_string(source, "ipAddress")?,
        port,
    })
}

fn check_object(value: &JsonElement, allowed: Option<&[&str]>) -> Option<()> {
    let JsonElement::Object(properties) = value else {
        return None;
    };
    let mut names = HashSet::new();
    for (name, _) in properties {
        if !names.insert(name) || allowed.is_some_and(|allowed| !allowed.contains(&name.as_str())) {
            return None;
        }
    }
    Some(())
}

fn optional_string(value: &JsonElement, name: &str) -> Option<Option<String>> {
    match value.get(name) {
        None | Some(JsonElement::Null) => Some(None),
        Some(JsonElement::String(text)) => Some(Some(text.clone())),
        _ => None,
    }
}

fn required_string(value: &JsonElement, name: &str) -> Option<String> {
    optional_string(value, name)?.filter(|text| !text.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_deny_explicit_trust_and_invalid_scope_files() {
        let candidate = r#"{"application":{"name":"x","environment":"test"}}"#;
        assert!(
            !ProducerAuthorization::new(None, false)
                .unwrap()
                .is_authorized("default", candidate)
        );
        assert!(
            ProducerAuthorization::new(None, true)
                .unwrap()
                .is_authorized("default", candidate)
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scopes.json");
        for json in [
            "{}",
            r#"[{"producer":"a","application":null}]"#,
            r#"[{"producer":"a","application":{"name":"x","name":"y","environment":"test"}}]"#,
            r#"[{"producer":"a","application":{"name":"x","environment":"test"},"sources":{}}]"#,
        ] {
            std::fs::write(&path, json).unwrap();
            let error = ProducerAuthorization::new(Some(&path), false)
                .err()
                .unwrap();
            assert_eq!(error.message, "Invalid producer scopes file.");
        }
        assert!(ProducerAuthorization::new(Some(&path), true).is_err());
    }

    #[test]
    fn credential_owner_null_source_and_duplicate_identity_are_exact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scopes.json");
        std::fs::write(
            &path,
            r#"[{"producer":"a","application":{"name":"x","environment":"test"}}]"#,
        )
        .unwrap();
        let authorization = ProducerAuthorization::new(Some(&path), false).unwrap();
        let candidate = r#"{"application":{"name":"x","environment":"test"}}"#;
        assert!(authorization.is_authorized("a", candidate));
        assert!(!authorization.is_authorized("b", candidate));
        assert!(!authorization.is_authorized(
            "a",
            r#"{"application":{"name":"y","name":"x","environment":"test"}}"#
        ));
        assert!(!authorization.is_authorized(
            "a",
            r#"{"application":{"name":"x","environment":"test"},"source":{"hostname":"other"}}"#
        ));
    }
}
