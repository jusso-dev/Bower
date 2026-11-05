//! `BOWER_S3_*` settings (C# `S3OutputOptions`). No credential setting exists: the client
//! uses the AWS default chain only, so no key is configured, stored or hashed by Bower.

pub const SSE_S3: &str = "AES256";
pub const SSE_KMS: &str = "aws:kms";
pub const DEFAULT_MAXIMUM_OBJECT_BYTES: i32 = 8 * 1024 * 1024;
pub const MINIMUM_OBJECT_BYTES: i32 = 1024 * 1024;
pub const MAXIMUM_OBJECT_BYTES_LIMIT: i32 = 64 * 1024 * 1024;
pub const DEFAULT_MAXIMUM_OBJECT_EVENTS: i32 = 1000;
pub const MAXIMUM_OBJECT_EVENTS_LIMIT: i32 = 100_000;

/// Static key settings Bower refuses: the default chain is the only credential source.
pub const REFUSED_CREDENTIAL_SETTINGS: [&str; 6] = [
    "BOWER_S3_ACCESS_KEY_ID",
    "BOWER_S3_SECRET_ACCESS_KEY",
    "BOWER_S3_SESSION_TOKEN",
    "BOWER_AWS_ACCESS_KEY_ID",
    "BOWER_AWS_SECRET_ACCESS_KEY",
    "BOWER_AWS_SESSION_TOKEN",
];

/// Invalid S3 settings; the message never echoes a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct S3SettingsError(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3OutputOptions {
    pub id: String,
    pub bucket: String,
    pub region: String,
    /// Key prefix without leading or trailing slash (`BOWER_S3_PREFIX`, default `bower`).
    pub prefix: String,
    /// `AES256` (SSE-S3, default) or `aws:kms` (`BOWER_S3_SSE`).
    pub server_side_encryption: String,
    /// KMS key id, alias or ARN for `aws:kms`; `None` uses the bucket's AWS managed key.
    pub kms_key_id: Option<String>,
    /// Twelve-digit account id sent as `ExpectedBucketOwner`.
    pub expected_bucket_owner: Option<String>,
    /// Uncompressed NDJSON bytes per object, newlines included.
    pub maximum_object_bytes: i32,
    pub maximum_object_events: i32,
    /// Gzip objects (`.jsonl.gz`); on by default.
    pub gzip: bool,
}

impl S3OutputOptions {
    /// Options with C# defaults for everything but the bucket and region.
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            id: "s3".into(),
            bucket: bucket.into(),
            region: region.into(),
            prefix: "bower".into(),
            server_side_encryption: SSE_S3.into(),
            kms_key_id: None,
            expected_bucket_owner: None,
            maximum_object_bytes: DEFAULT_MAXIMUM_OBJECT_BYTES,
            maximum_object_events: DEFAULT_MAXIMUM_OBJECT_EVENTS,
            gzip: true,
        }
    }

    /// C# `FromEnvironment`: `None` when no `BOWER_S3_*` setting is present. Static key
    /// settings are refused whether or not the S3 output is selected.
    pub fn from_environment(
        read: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, S3SettingsError> {
        for name in REFUSED_CREDENTIAL_SETTINGS {
            if read(name).is_some_and(|value| !value.is_empty()) {
                return Err(S3SettingsError(format!(
                    "{name} is not supported: the S3 output uses the AWS default credential chain only \
                     (IRSA/web identity, ECS or EC2 role, environment). Remove the setting."
                )));
            }
        }

        let value = |name: &str| {
            read(name)
                .filter(|value| !value.chars().all(char::is_whitespace))
                .map(|value| value.trim().to_string())
        };
        let bucket = value("BOWER_S3_BUCKET");
        let region = value("BOWER_S3_REGION");
        let prefix = value("BOWER_S3_PREFIX");
        let sse = value("BOWER_S3_SSE");
        let kms = value("BOWER_S3_KMS_KEY_ID");
        let owner = value("BOWER_S3_EXPECTED_BUCKET_OWNER");
        let bytes = value("BOWER_S3_MAX_OBJECT_BYTES");
        let events = value("BOWER_S3_MAX_OBJECT_EVENTS");
        let gzip = value("BOWER_S3_GZIP");
        if [
            &bucket, &region, &prefix, &sse, &kms, &owner, &bytes, &events, &gzip,
        ]
        .iter()
        .all(|item| item.is_none())
        {
            return Ok(None);
        }

        Ok(Some(Self {
            id: "s3".into(),
            bucket: bucket.unwrap_or_default(),
            region: region.unwrap_or_default(),
            prefix: prefix.unwrap_or_else(|| "bower".into()),
            server_side_encryption: match sse {
                None => SSE_S3.into(),
                Some(value) if value.eq_ignore_ascii_case(SSE_S3) => SSE_S3.into(),
                Some(value) if value.eq_ignore_ascii_case(SSE_KMS) => SSE_KMS.into(),
                Some(value) => value,
            },
            kms_key_id: kms,
            expected_bucket_owner: owner,
            maximum_object_bytes: read_int(
                bytes,
                "BOWER_S3_MAX_OBJECT_BYTES",
                DEFAULT_MAXIMUM_OBJECT_BYTES,
            )?,
            maximum_object_events: read_int(
                events,
                "BOWER_S3_MAX_OBJECT_EVENTS",
                DEFAULT_MAXIMUM_OBJECT_EVENTS,
            )?,
            gzip: match gzip {
                None => true,
                Some(value) if value.eq_ignore_ascii_case("true") => true,
                Some(value) if value.eq_ignore_ascii_case("false") => false,
                Some(_) => {
                    return Err(S3SettingsError(
                        "BOWER_S3_GZIP must be true or false.".into(),
                    ));
                }
            },
        }))
    }

    pub fn validate(&self) -> Result<(), S3SettingsError> {
        let fail = |message: &str| Err(S3SettingsError(message.into()));
        if !is_valid_bucket_name(&self.bucket) {
            return fail(
                "BOWER_S3_BUCKET must be an S3 bucket name: 3 to 63 lowercase letters, digits and hyphens, \
                 starting and ending with a letter or digit, without dots or reserved prefixes and suffixes.",
            );
        }
        if !is_valid_region(&self.region) {
            return fail("BOWER_S3_REGION must be an AWS region such as ap-southeast-2.");
        }
        if !is_valid_prefix(&self.prefix) {
            return fail(
                "BOWER_S3_PREFIX must be 1 to 512 characters of letters, digits and !-_.*'()= in segments \
                 separated by single slashes, without a leading or trailing slash or . and .. segments.",
            );
        }
        if self.server_side_encryption != SSE_S3 && self.server_side_encryption != SSE_KMS {
            return fail("BOWER_S3_SSE must be AES256 or aws:kms.");
        }
        if let Some(key) = &self.kms_key_id {
            if self.server_side_encryption != SSE_KMS {
                return fail("BOWER_S3_KMS_KEY_ID requires BOWER_S3_SSE=aws:kms.");
            }
            // C# counts UTF-16 code units; a key id is ASCII, so the counts agree.
            if key.encode_utf16().count() > 2048
                || key.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return fail(
                    "BOWER_S3_KMS_KEY_ID must be a KMS key id, alias or ARN without whitespace.",
                );
            }
        }
        if self
            .expected_bucket_owner
            .as_deref()
            .is_some_and(|owner| owner.len() != 12 || !owner.bytes().all(|b| b.is_ascii_digit()))
        {
            return fail("BOWER_S3_EXPECTED_BUCKET_OWNER must be a 12-digit AWS account id.");
        }
        if !(MINIMUM_OBJECT_BYTES..=MAXIMUM_OBJECT_BYTES_LIMIT).contains(&self.maximum_object_bytes)
        {
            return Err(S3SettingsError(format!(
                "BOWER_S3_MAX_OBJECT_BYTES must be between {MINIMUM_OBJECT_BYTES} and {MAXIMUM_OBJECT_BYTES_LIMIT}."
            )));
        }
        if !(1..=MAXIMUM_OBJECT_EVENTS_LIMIT).contains(&self.maximum_object_events) {
            return Err(S3SettingsError(format!(
                "BOWER_S3_MAX_OBJECT_EVENTS must be between 1 and {MAXIMUM_OBJECT_EVENTS_LIMIT}."
            )));
        }
        if self.id.chars().all(char::is_whitespace) {
            return fail("The S3 output id must not be blank.");
        }
        Ok(())
    }

    /// Non-secret settings for the collector configuration hash (C# `HashMaterial`).
    pub fn hash_material(&self) -> String {
        [
            self.bucket.as_str(),
            &self.region,
            &self.prefix,
            &self.server_side_encryption,
            self.kms_key_id.as_deref().unwrap_or_default(),
            self.expected_bucket_owner.as_deref().unwrap_or_default(),
            &self.maximum_object_bytes.to_string(),
            &self.maximum_object_events.to_string(),
            if self.gzip { "gzip" } else { "plain" },
        ]
        .join(",")
    }
}

/// S3 general purpose bucket naming rules, without dots (C# `IsValidBucketName`).
pub fn is_valid_bucket_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(3..=63).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        || bytes[0] == b'-'
        || bytes[bytes.len() - 1] == b'-'
    {
        return false;
    }
    !(["xn--", "sthree-", "amzn-s3-demo-"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || ["-s3alias", "--ol-s3", "--x-s3", "--table-s3"]
            .iter()
            .any(|suffix| value.ends_with(suffix)))
}

/// `^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$`.
fn is_valid_region(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() < 3 {
        return false;
    }
    let (first, rest) = (parts[0], &parts[1..]);
    let (number, middle) = rest.split_last().expect("at least two parts");
    first.len() == 2
        && first.bytes().all(|b| b.is_ascii_lowercase())
        && middle
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
        && (1..=2).contains(&number.len())
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// C# `IsValidPrefix`.
pub fn is_valid_prefix(value: &str) -> bool {
    (1..=512).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!_.*'()=/-".contains(&b))
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn read_int(value: Option<String>, name: &str, fallback: i32) -> Result<i32, S3SettingsError> {
    match value {
        None => Ok(fallback),
        // C# `int.TryParse(NumberStyles.Integer)` after the trim above: optional sign.
        Some(value) => value
            .parse::<i32>()
            .map_err(|_| S3SettingsError(format!("{name} must be an integer."))),
    }
}
