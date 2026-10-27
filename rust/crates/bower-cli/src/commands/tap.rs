//! `bower tap` (C# `TapAndTopCommands.TapAsync`): streams post-redaction outcomes from a
//! collector's `/v1/tap` as JSON lines on stdout (no file export). Sends
//! `BOWER_INGEST_TOKEN` when set and never prints it.

use std::io::Write;

use crate::cli::TapArgs;
use crate::support::{CliError, CliResult, ensure_slash};

/// Connect timeout only: a tap stream stays open for its whole session.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// C# `TapRefusal`.
pub fn refusal(status: u16, error: Option<&str>) -> String {
    match status {
        401 => "Tap refused: a valid collector ingest token is required (set BOWER_INGEST_TOKEN).".to_owned(),
        403 => "Tap refused: this credential may not tap (use the shared ingest token or a BOWER_TAP_PRODUCERS producer).".to_owned(),
        404 => "Tap is disabled on this collector (BOWER_TAP_ENABLED=false) or not supported.".to_owned(),
        429 => "Tap refused: the collector's concurrent tap session limit is reached; retry later.".to_owned(),
        _ => match error {
            Some(error) => format!("Tap refused: HTTP {status} ({error})."),
            None => format!("Tap refused: HTTP {status}."),
        },
    }
}

/// C# `Uri.EscapeDataString`: RFC 3986 unreserved characters stay, everything else is
/// percent-encoded as UTF-8.
fn escape_data(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

pub fn run(args: &TapArgs) -> CliResult {
    let collector = args
        .collector
        .clone()
        .unwrap_or_else(|| super::top::DEFAULT_COLLECTOR.to_owned());
    let stage = args.stage.as_deref().unwrap_or("redacted");
    if !matches!(stage, "redacted" | "decided" | "queued") {
        return Err(CliError::new(if matches!(stage, "parsed" | "raw") {
            "There is no pre-redaction tap point; the earliest is 'redacted'."
        } else {
            "--stage must be redacted, decided or queued."
        }));
    }
    let mut query = vec![format!("stage={stage}")];
    for (value, name) in [
        (&args.source, "source"),
        (&args.event_type, "eventType"),
        (&args.limit, "limit"),
        (&args.duration, "durationSeconds"),
        (&args.sample, "sample"),
    ] {
        if let Some(value) = value {
            query.push(format!("{name}={}", escape_data(value)));
        }
    }
    let base = reqwest::Url::parse(&ensure_slash(&collector)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let url = base
        .join(&format!("v1/tap?{}", query.join("&")))
        .map_err(CliError::from_display)?;
    super::block_on(async move {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(CliError::from_display)?;
        let mut request = client
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Ok(token) = std::env::var("BOWER_INGEST_TOKEN")
            && !token.is_empty()
        {
            request = request.bearer_auth(token);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| super::http_error(&error, CONNECT_TIMEOUT))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.bytes().await.unwrap_or_default();
            let error = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_owned));
            return Err(CliError(refusal(status.as_u16(), error.as_deref())));
        }
        let mut pending: Vec<u8> = Vec::new();
        let mut event_name = String::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| super::http_error(&error, CONNECT_TIMEOUT))?
        {
            pending.extend_from_slice(&chunk);
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                let line = line.strip_suffix('\r').unwrap_or(&line);
                if let Some(name) = line.strip_prefix("event: ") {
                    event_name = name.to_owned();
                } else if let Some(data) = line.strip_prefix("data: ") {
                    match event_name.as_str() {
                        "frame" => {
                            let mut stdout = std::io::stdout();
                            let _ = writeln!(stdout, "{data}");
                            let _ = stdout.flush();
                        }
                        "start" => eprintln!("tap started: {data}"),
                        "end" => {
                            eprintln!("tap ended: {data}");
                            return Ok(0);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_name_the_fix() {
        assert!(refusal(401, None).contains("BOWER_INGEST_TOKEN"));
        assert!(refusal(403, None).contains("BOWER_TAP_PRODUCERS"));
        assert_eq!(
            refusal(400, Some("tap-stage-invalid")),
            "Tap refused: HTTP 400 (tap-stage-invalid)."
        );
    }

    #[test]
    fn escapes_like_uri_escape_data_string() {
        assert_eq!(escape_data("auth.failure"), "auth.failure");
        assert_eq!(escape_data("a b&c"), "a%20b%26c");
    }
}
