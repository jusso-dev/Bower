//! IAM caller principal to producer mapping for Function URL requests.
//!
//! Lambda verifies the SigV4 signature and the resource policy before the handler
//! runs and passes the caller ARN in `requestContext.authorizer.iam.userArn`. This
//! map turns that ARN into a producer id; the producer's allowed event identities
//! then come from the collector's producer scopes file (same semantics, same
//! default deny). An unmapped caller is denied.
//!
//! File format (JSON, at most 1 MiB and 4096 entries):
//!
//! ```json
//! [{"principalArn": "arn:aws:iam::123456789012:role/orders-api", "producer": "orders"}]
//! ```
//!
//! Entries are IAM role or IAM user ARNs. A role entry matches sessions of that
//! role (`arn:aws:sts::<account>:assumed-role/<name>/<session>`); assumed-role ARNs
//! omit the role path, so role names are compared within the account. Root,
//! federated-user and service principals never match.

use std::collections::HashMap;
use std::path::Path;

use bower_contracts::JsonElement;

use crate::settings::SettingsError;

const MAXIMUM_FILE_BYTES: usize = 1_048_576;
const MAXIMUM_ENTRIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Role,
    User,
}

/// Normalised principal: partition, account, kind and name (path removed).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PrincipalKey {
    partition: String,
    account: String,
    kind: Kind,
    name: String,
}

#[derive(Default)]
pub struct PrincipalMap {
    producers: HashMap<PrincipalKey, String>,
}

impl PrincipalMap {
    /// `None` path: no Function URL caller is mapped (all denied).
    pub fn load(path: Option<&Path>) -> Result<Self, SettingsError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let text = std::fs::read_to_string(path)
            .map_err(|_| SettingsError::new("BOWER_LAMBDA_PRINCIPALS_FILE could not be read."))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, SettingsError> {
        let invalid = || SettingsError::new("Invalid principals file.");
        if text.len() > MAXIMUM_FILE_BYTES {
            return Err(invalid());
        }
        let root =
            JsonElement::parse(text.trim_start_matches('\u{feff}')).map_err(|_| invalid())?;
        let JsonElement::Array(items) = root else {
            return Err(invalid());
        };
        if items.len() > MAXIMUM_ENTRIES {
            return Err(invalid());
        }
        let mut producers = HashMap::new();
        for item in items {
            let JsonElement::Object(properties) = &item else {
                return Err(invalid());
            };
            let mut principal = None;
            let mut producer = None;
            for (name, value) in properties {
                let (slot, JsonElement::String(text)) = (
                    match name.as_str() {
                        "principalArn" => &mut principal,
                        "producer" => &mut producer,
                        _ => return Err(invalid()),
                    },
                    value,
                ) else {
                    return Err(invalid());
                };
                if slot.replace(text.clone()).is_some() {
                    return Err(invalid());
                }
            }
            let (Some(principal), Some(producer)) = (principal, producer) else {
                return Err(invalid());
            };
            if !valid_producer(&producer) {
                return Err(invalid());
            }
            let key = parse_configured(&principal).ok_or_else(invalid)?;
            if producers.insert(key, producer).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self { producers })
    }

    /// The producer for a verified caller ARN, or `None` (deny).
    pub fn producer_for(&self, caller_arn: &str) -> Option<&str> {
        let key = parse_caller(caller_arn)?;
        self.producers.get(&key).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.producers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.producers.is_empty()
    }
}

/// Producer ids follow the producer scopes rules: 1-64 UTF-16 units, no whitespace.
pub fn valid_producer(value: &str) -> bool {
    let units = value.encode_utf16().count();
    (1..=64).contains(&units) && !value.chars().any(char::is_whitespace)
}

fn valid_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'-')
        })
}

fn valid_path(value: &str) -> bool {
    value.len() <= 512 && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// `arn:<partition>:<service>::<account>:<resource>` split into parts.
fn split_arn(arn: &str) -> Option<(&str, &str, &str, &str)> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let [prefix, partition, service, region, account, resource] = parts.as_slice() else {
        return None;
    };
    let partition_ok = partition.starts_with("aws")
        && partition
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
    let account_ok = account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit());
    (*prefix == "arn" && partition_ok && region.is_empty() && account_ok)
        .then_some((*partition, *service, *account, *resource))
}

/// `role/<path/>name` or `user/<path/>name` in IAM.
fn iam_resource(resource: &str) -> Option<(Kind, &str)> {
    let (kind, rest) = match resource.strip_prefix("role/") {
        Some(rest) => (Kind::Role, rest),
        None => (Kind::User, resource.strip_prefix("user/")?),
    };
    let (path, name) = rest.rsplit_once('/').unwrap_or(("", rest));
    (valid_path(path) && valid_name(name)).then_some((kind, name))
}

fn parse_configured(arn: &str) -> Option<PrincipalKey> {
    let (partition, service, account, resource) = split_arn(arn)?;
    if service != "iam" {
        return None;
    }
    let (kind, name) = iam_resource(resource)?;
    Some(PrincipalKey {
        partition: partition.into(),
        account: account.into(),
        kind,
        name: name.into(),
    })
}

fn parse_caller(arn: &str) -> Option<PrincipalKey> {
    let (partition, service, account, resource) = split_arn(arn)?;
    let (kind, name) = match service {
        "iam" => iam_resource(resource)?,
        "sts" => {
            let rest = resource.strip_prefix("assumed-role/")?;
            let (name, session) = rest.split_once('/')?;
            if !valid_name(name) || session.is_empty() || session.len() > 64 {
                return None;
            }
            (Kind::Role, name)
        }
        _ => return None,
    };
    Some(PrincipalKey {
        partition: partition.into(),
        account: account.into(),
        kind,
        name: name.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = r#"[
        {"principalArn": "arn:aws:iam::123456789012:role/apps/orders-api", "producer": "orders"},
        {"principalArn": "arn:aws:iam::123456789012:user/ci-forwarder", "producer": "ci"}
    ]"#;

    #[test]
    fn maps_role_sessions_and_users_exactly() {
        let map = PrincipalMap::parse(MAP).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.producer_for("arn:aws:sts::123456789012:assumed-role/orders-api/i-0abc"),
            Some("orders")
        );
        assert_eq!(
            map.producer_for("arn:aws:iam::123456789012:user/ci-forwarder"),
            Some("ci")
        );
        for denied in [
            "arn:aws:sts::210987654321:assumed-role/orders-api/s",
            "arn:aws:sts::123456789012:assumed-role/orders-api-2/s",
            "arn:aws:sts::123456789012:assumed-role/Orders-Api/s",
            "arn:aws-cn:sts::123456789012:assumed-role/orders-api/s",
            "arn:aws:iam::123456789012:root",
            "arn:aws:sts::123456789012:federated-user/orders-api",
            "arn:aws:iam::123456789012:user/other/ci-forwarder-x",
            "arn:aws:sts::123456789012:assumed-role/orders-api",
            "",
            "orders",
        ] {
            assert_eq!(map.producer_for(denied), None, "{denied}");
        }
        assert_eq!(
            PrincipalMap::default().producer_for("arn:aws:iam::123456789012:user/ci-forwarder"),
            None
        );
    }

    #[test]
    fn rejects_malformed_or_ambiguous_files() {
        for text in [
            "{}",
            "[1]",
            r#"[{"principalArn": "arn:aws:iam::123456789012:role/a"}]"#,
            r#"[{"principalArn": "arn:aws:iam::123456789012:role/a", "producer": "a", "x": "y"}]"#,
            r#"[{"principalArn": "arn:aws:iam::123456789012:role/a", "producer": "has space"}]"#,
            r#"[{"principalArn": "arn:aws:iam::123456789012:role/a", "producer": "a", "producer": "b"}]"#,
            r#"[{"principalArn": "arn:aws:iam::123456789012:root", "producer": "a"}]"#,
            r#"[{"principalArn": "arn:aws:sts::123456789012:assumed-role/a/s", "producer": "a"}]"#,
            r#"[{"principalArn": "arn:aws:iam::123456789012:role/x/a", "producer": "a"},
                {"principalArn": "arn:aws:iam::123456789012:role/y/a", "producer": "b"}]"#,
        ] {
            assert_eq!(
                PrincipalMap::parse(text).err(),
                Some(SettingsError::new("Invalid principals file.")),
                "{text}"
            );
        }
    }
}
