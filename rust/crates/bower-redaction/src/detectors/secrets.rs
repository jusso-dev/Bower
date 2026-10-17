//! Cloud, auth and credential secrets.

use std::sync::LazyLock;

use regex::Regex;

use super::{DetectionMatch, RegexDetector, ScanText, SensitiveDetector, compile};
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::text::contains_ignore_ascii_case;

static AWS: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|(?:aws)?_?secret_?(?:access)?_?key\s*[:=]\s*\S+|aws_session_token\s*[:=]\s*\S+",
    )
});
static AZURE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}|sv=\d{4}-\d{2}-\d{2}[^;\s]*sig=[A-Za-z0-9%]+|SharedAccessSignature=[^\s;]+|AccountKey=[A-Za-z0-9+/=]{40,}",
    )
});
static ENTRA: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|device_code\s*[:=]\s*[A-Za-z0-9\-_]{10,}",
    )
});
static GCP: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#""type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN|AIza[0-9A-Za-z\-_]{35}|ya29\.[0-9A-Za-z\-_]+"#,
    )
});
static JWT: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"));
static OAUTH: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:access_token|refresh_token|id_token)\s*[:=]\s*[A-Za-z0-9\-._~+/]+=*")
});
static KUBERNETES: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|kubeconfig|kind:\s*Config[\s\S]{0,80}users:|Bearer\s+eyJ[A-Za-z0-9_-]+\.",
    )
});
static DOCKER: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i)\b(?:docker\s+login|auths\s*\{|"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}")\b|registry[^\n]{0,40}password\s*[:=]\s*\S+"#,
    )
});
static DATABASE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)(?:Server|Data Source|Host)=[^;]+;.*(?:Password|Pwd)=[^;]+|jdbc:[a-z0-9]+:\/\/[^\s]+|postgres(?:ql)?:\/\/[^\s]+|mysql:\/\/[^\s]+|mongodb(?:\+srv)?:\/\/[^\s]+|Driver=\{[^}]+\}.*Pwd=",
    )
});
static ENV_VAR: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"\b(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|AUTH_TOKEN)\s*=\s*\S+",
    )
});

fn aws_sub_kind(matched: &str) -> Option<String> {
    let kind = if matched.starts_with("AKIA") || matched.starts_with("ASIA") {
        "access-key-id"
    } else if matched.contains("ASIA") || contains_ignore_ascii_case(matched, "session") {
        "session-token"
    } else {
        "secret-access-key"
    };
    Some(kind.to_owned())
}

pub fn aws_secret_detector() -> RegexDetector {
    RegexDetector::new(ids::AWS, categories::SECRETS, &AWS).with_sub_kind(aws_sub_kind)
}

pub fn azure_secret_detector() -> RegexDetector {
    RegexDetector::new(ids::AZURE, categories::SECRETS, &AZURE)
}

pub fn entra_token_detector() -> RegexDetector {
    RegexDetector::new(ids::ENTRA, categories::SECRETS, &ENTRA)
}

pub fn gcp_secret_detector() -> RegexDetector {
    RegexDetector::new(ids::GCP, categories::SECRETS, &GCP)
}

/// Three Base64URL segments separated by `.` with a JSON (`eyJ`) header.
fn validate_jwt(matched: &str) -> bool {
    let Some(first) = matched.find('.') else {
        return false;
    };
    if first == 0 {
        return false;
    }

    let Some(second) = matched[first + 1..].find('.') else {
        return false;
    };
    if second == 0 {
        return false;
    }

    // Matches are ASCII, so byte offsets equal UTF-16 offsets.
    let second_absolute = first + 1 + second;
    if second_absolute + 1 >= matched.len() {
        return false;
    }

    matched.starts_with("eyJ")
}

pub fn jwt_detector() -> RegexDetector {
    RegexDetector::new(ids::JWT, categories::SECRETS, &JWT).with_validation(validate_jwt)
}

pub fn oauth_token_detector() -> RegexDetector {
    RegexDetector::new(ids::OAUTH, categories::SECRETS, &OAUTH)
}

pub fn kubernetes_secret_detector() -> RegexDetector {
    RegexDetector::new(ids::KUBERNETES, categories::SECRETS, &KUBERNETES)
}

pub fn docker_credential_detector() -> RegexDetector {
    RegexDetector::new(ids::DOCKER, categories::SECRETS, &DOCKER)
}

pub fn database_credential_detector() -> RegexDetector {
    RegexDetector::new(ids::DATABASE, categories::SECRETS, &DATABASE)
}

pub fn environment_variable_secret_detector() -> RegexDetector {
    RegexDetector::new(ids::ENV_VAR, categories::SECRETS, &ENV_VAR)
}

/// Provider API key patterns. New providers are registered without changing the engine.
static API_KEY_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("OpenAI", r"\bsk-[A-Za-z0-9]{20,}\b"),
        ("Anthropic", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        ("GitHub", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        ("GitLab", r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
        ("Slack", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        ("Stripe", r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        ("Twilio", r"\bSK[0-9a-fA-F]{32}\b"),
        ("Cloudflare", r"\b(?:cfx|v1\.0-)[A-Za-z0-9_\-]{20,}\b"),
        ("Atlassian", r"\bATATT3[A-Za-z0-9=_\-]{20,}\b"),
        ("Datadog", r"\b(?:[a-f0-9]{32}|ddog_api_key)\b"),
        // Only with context, see `detect`.
        ("PagerDuty", r"\b[a-f0-9]{32}\b"),
        ("Okta", r"\b00[A-Za-z0-9_\-]{40,}\b"),
        ("MongoDB", r"\bmongodb(?:\+srv)?:\/\/[^\s]+\b"),
        (
            "Snowflake",
            r"\b[A-Za-z0-9]{8,}-[A-Za-z0-9]{4,}\.[A-Za-z0-9]+\.snowflakecomputing\.com\b",
        ),
    ]
    .into_iter()
    .map(|(provider, pattern)| (provider, compile(pattern)))
    .collect()
});

pub struct ApiKeyDetector;

impl SensitiveDetector for ApiKeyDetector {
    fn id(&self) -> &str {
        ids::API_KEY
    }

    fn category(&self) -> &str {
        categories::SECRETS
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        let original = text.text();
        for (provider, regex) in API_KEY_PATTERNS.iter() {
            // High false-positive patterns need context.
            if matches!(*provider, "PagerDuty" | "Datadog")
                && !contains_ignore_ascii_case(original, provider)
                && !contains_ignore_ascii_case(original, "api_key")
                && !contains_ignore_ascii_case(original, "apikey")
            {
                continue;
            }

            for found in regex.find_iter(text.haystack()) {
                matches.push(text.detection(
                    ids::API_KEY,
                    categories::SECRETS,
                    &found,
                    false,
                    Some((*provider).to_owned()),
                ));
            }
        }
    }
}
