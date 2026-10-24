//! `LambdaSettings`: read once from environment variables at cold start and
//! validated before the first invocation. Names follow the collector's `BOWER_*`
//! variables where the meaning is the same; Lambda-only settings use
//! `BOWER_LAMBDA_*` and `BOWER_CLOUDTRAIL_*`.
//!
//! Fail closed: unknown ingress modes, malformed ARNs and settings that only make
//! sense for the bearer-token collector (or would place a secret in the package)
//! stop the function at init instead of being ignored.

use std::path::PathBuf;

use bower_collector::CollectorSettings;
use sha2::{Digest, Sha256};

/// The one invocation path a deployment accepts. URL and direct-Invoke ingress are
/// separate deployments (separate functions or stacks), never one function serving
/// both: a direct invoker of a URL function could otherwise present a URL-shaped
/// payload with any caller ARN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// Only Function URL events (`AuthType: AWS_IAM`). Direct payloads that are not
    /// URL-shaped are refused; URL-shaped direct payloads cannot be told apart, so
    /// IAM must keep direct invokers out (resource policy plus the shipped Deny).
    FunctionUrl,
    /// Only direct `Invoke` payloads, attributed to `BOWER_LAMBDA_INVOKE_PRODUCER`.
    /// Function URL shaped events are refused, so an invoker cannot forge a caller.
    Invoke,
}

impl Ingress {
    fn parse(value: Option<&str>) -> Result<Self, SettingsError> {
        match value
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("function-url") => Ok(Self::FunctionUrl),
            Some("invoke") => Ok(Self::Invoke),
            Some("both") => Err(SettingsError::new(
                "BOWER_LAMBDA_INGRESS=both is not supported; deploy separate function-url and \
                 invoke functions.",
            )),
            Some(_) => Err(SettingsError::new(
                "BOWER_LAMBDA_INGRESS must be function-url or invoke.",
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::FunctionUrl => "function-url",
            Self::Invoke => "invoke",
        }
    }

    pub fn allows_function_url(self) -> bool {
        self == Self::FunctionUrl
    }

    pub fn allows_invoke(self) -> bool {
        self == Self::Invoke
    }
}

/// A configuration error. Messages name variables, never their values.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SettingsError(pub String);

impl SettingsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Clone, PartialEq)]
pub struct LambdaSettings {
    pub channel_arn: String,
    /// Account that owns the channel (`recipientAccountId` in every audit event).
    pub recipient_account_id: String,
    pub external_id: Option<String>,
    pub ingress: Ingress,
    /// Producer id used for direct `Invoke` payloads (Lambda passes no caller identity).
    pub invoke_producer: Option<String>,
    /// IAM principal to producer mapping for Function URL callers.
    pub principals_file: Option<PathBuf>,
    pub producer_scopes_file: Option<PathBuf>,
    pub single_trust_domain: bool,
    pub policy_directory: PathBuf,
    pub packs: Vec<String>,
    pub pack_trusted_key_files: Vec<String>,
    pub privacy_profile_path: Option<PathBuf>,
    pub privacy_hmac_key_secret_arn: Option<String>,
    pub privacy_hmac_key_id: String,
    pub collector_id: String,
    pub version: String,
}

// Settings hold no secret values, but keep Debug to identifiers only.
impl std::fmt::Debug for LambdaSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LambdaSettings")
            .field("collector_id", &self.collector_id)
            .field("ingress", &self.ingress)
            .finish_non_exhaustive()
    }
}

impl LambdaSettings {
    pub fn from_process_environment() -> Result<Self, SettingsError> {
        Self::from_environment(|name| std::env::var(name).ok())
    }

    /// `read` returns `None` for unset variables. Blank values count as unset.
    pub fn from_environment(read: impl Fn(&str) -> Option<String>) -> Result<Self, SettingsError> {
        let value = |name: &str| read(name).filter(|value| !is_blank(value));

        for name in [
            "BOWER_INGEST_TOKEN",
            "BOWER_INGEST_TOKEN_FILE",
            "BOWER_INGEST_TOKENS_FILE",
            "BOWER_ALLOW_UNAUTHENTICATED_INGEST",
        ] {
            if value(name).is_some() {
                return Err(SettingsError::new(format!(
                    "{name} is not supported by the Lambda host; callers authenticate with IAM only."
                )));
            }
        }
        // Serverless hosts have no managed profile sync: only a packaged, reviewed
        // profile (or the default) is used, so refuse anything else loudly.
        if let Some(source) = value("BOWER_PRIVACY_PROFILE_SOURCE") {
            match source.trim().to_ascii_lowercase().as_str() {
                "local" => {}
                "management" => {
                    return Err(SettingsError::new(
                        "BOWER_PRIVACY_PROFILE_SOURCE=management is not supported by the AWS \
                         Lambda host; package a reviewed privacy profile.",
                    ));
                }
                _ => {
                    return Err(SettingsError::new(
                        "BOWER_PRIVACY_PROFILE_SOURCE must be local for the AWS Lambda host; \
                         package a reviewed privacy profile.",
                    ));
                }
            }
        }
        if value("BOWER_PRIVACY_HMAC_KEY_FILE").is_some() {
            return Err(SettingsError::new(
                "BOWER_PRIVACY_HMAC_KEY_FILE is not supported by the Lambda host; a key file would be \
                 packaged with the code. Use BOWER_PRIVACY_HMAC_KEY_SECRET_ARN.",
            ));
        }

        let channel_arn = value("BOWER_CLOUDTRAIL_CHANNEL_ARN")
            .ok_or_else(|| SettingsError::new("BOWER_CLOUDTRAIL_CHANNEL_ARN is required."))?
            .trim()
            .to_string();
        let channel_account = channel_account_id(&channel_arn).ok_or_else(|| {
            SettingsError::new(
                "BOWER_CLOUDTRAIL_CHANNEL_ARN must be arn:<partition>:cloudtrail:<region>:<account>:channel/<id>.",
            )
        })?;
        let recipient_account_id = match value("BOWER_CLOUDTRAIL_RECIPIENT_ACCOUNT_ID") {
            Some(account) if account.trim() == channel_account => account.trim().to_string(),
            Some(_) => {
                return Err(SettingsError::new(
                    "BOWER_CLOUDTRAIL_RECIPIENT_ACCOUNT_ID must equal the account that owns the channel.",
                ));
            }
            None => channel_account.to_string(),
        };
        let external_id = value("BOWER_CLOUDTRAIL_EXTERNAL_ID");
        if let Some(external_id) = &external_id
            && !valid_external_id(external_id)
        {
            return Err(SettingsError::new(
                "BOWER_CLOUDTRAIL_EXTERNAL_ID must be 2-1224 characters of [A-Za-z0-9_+=,.@:/-].",
            ));
        }

        let invoke_producer = value("BOWER_LAMBDA_INVOKE_PRODUCER").map(|v| v.trim().to_string());
        if let Some(producer) = &invoke_producer
            && !crate::principals::valid_producer(producer)
        {
            return Err(SettingsError::new(
                "BOWER_LAMBDA_INVOKE_PRODUCER must be 1-64 characters without whitespace.",
            ));
        }

        let ingress = Ingress::parse(read("BOWER_LAMBDA_INGRESS").as_deref())?;
        let principals_file = value("BOWER_LAMBDA_PRINCIPALS_FILE").map(PathBuf::from);
        match ingress {
            Ingress::FunctionUrl if invoke_producer.is_some() => {
                return Err(SettingsError::new(
                    "BOWER_LAMBDA_INVOKE_PRODUCER is only used with BOWER_LAMBDA_INGRESS=invoke; \
                     a Function URL deployment never accepts direct invokes.",
                ));
            }
            Ingress::FunctionUrl if principals_file.is_none() => {
                return Err(SettingsError::new(
                    "BOWER_LAMBDA_PRINCIPALS_FILE is required with BOWER_LAMBDA_INGRESS=function-url.",
                ));
            }
            Ingress::Invoke if invoke_producer.is_none() => {
                return Err(SettingsError::new(
                    "BOWER_LAMBDA_INVOKE_PRODUCER is required with BOWER_LAMBDA_INGRESS=invoke.",
                ));
            }
            Ingress::Invoke if principals_file.is_some() => {
                return Err(SettingsError::new(
                    "BOWER_LAMBDA_PRINCIPALS_FILE is only used with BOWER_LAMBDA_INGRESS=function-url.",
                ));
            }
            _ => {}
        }

        let privacy_hmac_key_secret_arn =
            value("BOWER_PRIVACY_HMAC_KEY_SECRET_ARN").map(|v| v.trim().to_string());
        if let Some(arn) = &privacy_hmac_key_secret_arn
            && !valid_secret_arn(arn)
        {
            return Err(SettingsError::new(
                "BOWER_PRIVACY_HMAC_KEY_SECRET_ARN must be a full Secrets Manager secret ARN.",
            ));
        }

        let single_trust_domain = value("BOWER_SINGLE_TRUST_DOMAIN")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
        let producer_scopes_file = value("BOWER_PRODUCER_SCOPES_FILE").map(PathBuf::from);
        if single_trust_domain && producer_scopes_file.is_some() {
            return Err(SettingsError::new(
                "Producer scopes and single trust domain mode are mutually exclusive.",
            ));
        }
        let packs = split_list(value("BOWER_PACKS").as_deref());
        let pack_trusted_key_files = split_list(value("BOWER_PACK_TRUSTED_KEYS").as_deref());
        if !packs.is_empty() && pack_trusted_key_files.is_empty() {
            return Err(SettingsError::new(
                "BOWER_PACKS requires BOWER_PACK_TRUSTED_KEYS; packs are never loaded unverified.",
            ));
        }

        Ok(Self {
            channel_arn,
            recipient_account_id,
            external_id,
            ingress,
            invoke_producer,
            principals_file,
            producer_scopes_file,
            single_trust_domain,
            policy_directory: value("BOWER_POLICY_DIRECTORY")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join("policies")
                        .join("default")
                }),
            packs,
            pack_trusted_key_files,
            privacy_profile_path: value("BOWER_PRIVACY_PROFILE").map(PathBuf::from),
            privacy_hmac_key_secret_arn,
            privacy_hmac_key_id: value("BOWER_PRIVACY_HMAC_KEY_ID").unwrap_or_else(|| "k1".into()),
            collector_id: value("BOWER_COLLECTOR_ID")
                .or_else(|| value("AWS_LAMBDA_FUNCTION_NAME"))
                .unwrap_or_else(|| "bower-lambda".into()),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    /// The collector settings the shared policy bundle loader reads (policies,
    /// packs, privacy profile and key id). Nothing else in them is used.
    pub fn bundle_settings(&self) -> CollectorSettings {
        let mut settings = CollectorSettings::new(
            "http://127.0.0.1:4319",
            "/tmp/bower-lambda-unused.db",
            self.policy_directory.clone(),
            self.collector_id.clone(),
        );
        settings.packs = self.packs.clone();
        settings.pack_trusted_key_files = self.pack_trusted_key_files.clone();
        settings.privacy_profile_path = self.privacy_profile_path.clone();
        settings.privacy_hmac_key_id = self.privacy_hmac_key_id.clone();
        settings
    }

    /// Hash of non-secret settings stamped into `collector.configurationHash`.
    pub fn configuration_hash(&self) -> String {
        let material = [
            "aws-lambda-cloudtrail-lake".to_string(),
            self.channel_arn.clone(),
            self.recipient_account_id.clone(),
            self.ingress.name().to_string(),
            self.invoke_producer.clone().unwrap_or_default(),
            self.privacy_hmac_key_id.clone(),
            self.single_trust_domain.to_string(),
            path_text(self.producer_scopes_file.as_ref()),
            path_text(self.principals_file.as_ref()),
            self.external_id.is_some().to_string(),
        ]
        .join("\u{1f}");
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(material.as_bytes()))
        )
    }
}

fn path_text(path: Option<&PathBuf>) -> String {
    path.map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

fn split_list(value: Option<&str>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split([',', ';'])
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn is_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_partition(value: &str) -> bool {
    value.starts_with("aws")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
}

fn is_region(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Account id of `arn:<partition>:cloudtrail:<region>:<account>:channel/<id>`.
pub fn channel_account_id(arn: &str) -> Option<&str> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let [prefix, partition, service, region, account, resource] = parts.as_slice() else {
        return None;
    };
    let id = resource.strip_prefix("channel/")?;
    let valid = *prefix == "arn"
        && is_partition(partition)
        && *service == "cloudtrail"
        && is_region(region)
        && is_account_id(account)
        && !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    valid.then_some(account)
}

fn valid_secret_arn(arn: &str) -> bool {
    let parts: Vec<&str> = arn.splitn(7, ':').collect();
    let [prefix, partition, service, region, account, kind, name] = parts.as_slice() else {
        return false;
    };
    *prefix == "arn"
        && is_partition(partition)
        && *service == "secretsmanager"
        && is_region(region)
        && is_account_id(account)
        && *kind == "secret"
        && !name.is_empty()
        && name.len() <= 512
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'_' | b'+' | b'=' | b'.' | b'@' | b'-')
        })
}

/// `PutAuditEvents` `externalId`: 2-1224 characters of `[\w+=,.@:\/-]`.
fn valid_external_id(value: &str) -> bool {
    (2..=1224).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b':' | b'/' | b'-'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CHANNEL: &str = "arn:aws:cloudtrail:ap-southeast-2:123456789012:channel/01234567-89ab-cdef-0123-456789abcdef";

    fn read(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn reads_defaults_and_derives_recipient_account() {
        let settings = LambdaSettings::from_environment(read(&[
            ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
            ("BOWER_LAMBDA_PRINCIPALS_FILE", "/var/task/principals.json"),
            ("AWS_LAMBDA_FUNCTION_NAME", "bower-ingest"),
        ]))
        .unwrap();
        assert_eq!(settings.recipient_account_id, "123456789012");
        assert_eq!(settings.ingress, Ingress::FunctionUrl);
        assert_eq!(settings.collector_id, "bower-ingest");
        assert_eq!(settings.privacy_hmac_key_id, "k1");
        assert!(settings.invoke_producer.is_none());
        assert!(settings.configuration_hash().starts_with("sha256:"));
    }

    #[test]
    fn fails_closed_on_unsafe_or_invalid_configuration() {
        let cases: &[&[(&str, &str)]] = &[
            &[],
            &[(
                "BOWER_CLOUDTRAIL_CHANNEL_ARN",
                "arn:aws:cloudtrail:ap-southeast-2:1234:channel/x",
            )],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_INGEST_TOKEN", "x".repeat(40).leak()),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_PRIVACY_HMAC_KEY_FILE", "/var/task/key"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_LAMBDA_INGRESS", "public"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_LAMBDA_INVOKE_PRODUCER", "has space"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_CLOUDTRAIL_EXTERNAL_ID", "x"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_CLOUDTRAIL_RECIPIENT_ACCOUNT_ID", "210987654321"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_PRIVACY_HMAC_KEY_SECRET_ARN", "my-secret"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_PACKS", "/var/task/a.bowerpack"),
            ],
            &[
                ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
                ("BOWER_SINGLE_TRUST_DOMAIN", "true"),
                ("BOWER_PRODUCER_SCOPES_FILE", "/var/task/scopes.json"),
            ],
        ];
        for case in cases {
            let error = LambdaSettings::from_environment(read(case)).unwrap_err();
            for (_, value) in case.iter().skip(1) {
                assert!(
                    !error.0.contains(value),
                    "error echoes a value: {}",
                    error.0
                );
            }
        }
    }

    #[test]
    fn accepts_secret_arn_and_external_id() {
        let settings = LambdaSettings::from_environment(read(&[
            ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL),
            (
                "BOWER_PRIVACY_HMAC_KEY_SECRET_ARN",
                "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:bower/privacy-hmac-AbCdEf",
            ),
            ("BOWER_CLOUDTRAIL_EXTERNAL_ID", "bower-prod:2026"),
            ("BOWER_LAMBDA_INGRESS", "Invoke"),
            ("BOWER_LAMBDA_INVOKE_PRODUCER", "batch-forwarder"),
            ("BOWER_PRIVACY_PROFILE_SOURCE", "Local"),
        ]))
        .unwrap();
        assert_eq!(settings.ingress, Ingress::Invoke);
        assert!(settings.privacy_hmac_key_secret_arn.is_some());
        assert_eq!(settings.external_id.as_deref(), Some("bower-prod:2026"));
        let bundle = settings.bundle_settings();
        assert_eq!(bundle.privacy_hmac_key_id, "k1");
        assert!(bundle.privacy_hmac_key_file.is_none());
    }

    /// Council review B1 and B4: mixed ingress, mismatched ingress settings and a
    /// managed privacy profile source never start.
    #[test]
    fn rejects_mixed_ingress_and_managed_profiles() {
        let principals = ("BOWER_LAMBDA_PRINCIPALS_FILE", "/var/task/principals.json");
        let producer = ("BOWER_LAMBDA_INVOKE_PRODUCER", "batch");
        let channel = ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL);
        let cases: &[(&[(&str, &str)], &str)] = &[
            (
                &[
                    channel,
                    ("BOWER_LAMBDA_INGRESS", "both"),
                    principals,
                    producer,
                ],
                "BOWER_LAMBDA_INGRESS=both is not supported",
            ),
            (
                &[channel, principals, producer],
                "only used with BOWER_LAMBDA_INGRESS=invoke",
            ),
            (&[channel], "BOWER_LAMBDA_PRINCIPALS_FILE is required"),
            (
                &[channel, ("BOWER_LAMBDA_INGRESS", "invoke")],
                "BOWER_LAMBDA_INVOKE_PRODUCER is required",
            ),
            (
                &[
                    channel,
                    ("BOWER_LAMBDA_INGRESS", "invoke"),
                    producer,
                    principals,
                ],
                "only used with BOWER_LAMBDA_INGRESS=function-url",
            ),
            (
                &[
                    channel,
                    principals,
                    ("BOWER_PRIVACY_PROFILE_SOURCE", "management"),
                ],
                "BOWER_PRIVACY_PROFILE_SOURCE=management is not supported by the AWS Lambda host; \
                 package a reviewed privacy profile.",
            ),
            (
                &[
                    channel,
                    principals,
                    ("BOWER_PRIVACY_PROFILE_SOURCE", "Management "),
                ],
                "BOWER_PRIVACY_PROFILE_SOURCE=management is not supported",
            ),
            (
                &[channel, principals, ("BOWER_PRIVACY_PROFILE_SOURCE", "s3")],
                "BOWER_PRIVACY_PROFILE_SOURCE must be local",
            ),
        ];
        for (environment, expected) in cases {
            let error = LambdaSettings::from_environment(read(environment)).unwrap_err();
            assert!(error.0.contains(expected), "{} / {}", error.0, expected);
        }
    }
}
