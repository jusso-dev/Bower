//! `bower top` (C# `TapAndTopCommands.TopAsync` and `TopView`): per-stage throughput,
//! intake, sources, syslog listeners, queue, delivery and tap counters from two
//! `/v1/status` samples. Rendering is pure and byte-identical to C# (shared fixtures in
//! `tests/fixtures/top`). Rates use integer tenths, never floats. Metadata only.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use bower_contracts::time::Timestamp;
use serde_json::Value;

use crate::cli::TopArgs;
use crate::support::{CliError, CliResult, ensure_slash};

pub const DEFAULT_COLLECTOR: &str = "http://127.0.0.1:4319";
const STAGE_ORDER: [&str; 5] = ["transform", "redaction", "schema", "validation", "policy"];
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-second rate in tenths; "-" without a previous sample or after a counter reset.
pub fn rate_text(current: i64, previous: i64, has_previous: bool, elapsed_ms: i64) -> String {
    if !has_previous || elapsed_ms <= 0 || current < previous {
        return "-".to_owned();
    }
    decimal(((current - previous) * 10_000 + elapsed_ms / 2) / elapsed_ms)
}

fn decimal(tenths: i64) -> String {
    format!("{}.{}", tenths / 10, tenths % 10)
}

#[derive(Clone, Copy)]
struct Cell<'a> {
    text: &'a str,
    width: usize,
    right: bool,
}

fn l(text: &str, width: usize) -> Cell<'_> {
    Cell {
        text,
        width,
        right: false,
    }
}

fn r(text: &str, width: usize) -> Cell<'_> {
    Cell {
        text,
        width,
        right: true,
    }
}

/// C# `PadLeft`/`PadRight` count UTF-16 units.
fn pad(cell: Cell<'_>) -> String {
    let length = cell.text.encode_utf16().count();
    let fill = " ".repeat(cell.width.saturating_sub(length));
    if cell.right {
        format!("{fill}{}", cell.text)
    } else {
        format!("{}{fill}", cell.text)
    }
}

/// Cells padded to their width, one space apart, trailing spaces trimmed.
fn row(cells: &[Cell<'_>]) -> String {
    cells
        .iter()
        .map(|cell| pad(*cell))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end()
        .to_owned()
}

fn property<'a>(value: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    value
        .and_then(|value| value.as_object())
        .and_then(|object| object.get(name))
}

fn text<'a>(value: Option<&'a Value>, name: &str) -> &'a str {
    property(value, name).and_then(Value::as_str).unwrap_or("-")
}

fn number(value: Option<&Value>, name: &str) -> i64 {
    property(value, name).and_then(Value::as_i64).unwrap_or(0)
}

fn array<'a>(value: Option<&'a Value>, name: &str) -> Vec<&'a Value> {
    property(value, name)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn sum(rows: &[&Value], name: &str) -> i64 {
    rows.iter().map(|row| number(Some(row), name)).sum()
}

fn stage_row(stage: &str, rows: &[&Value], events: i64, rate: &str) -> String {
    let count = |actions: &[&str]| -> i64 {
        rows.iter()
            .filter(|row| actions.contains(&text(Some(row), "action")))
            .map(|row| number(Some(row), "events"))
            .sum()
    };
    let accepted = count(&["accept", "redact-and-accept"]);
    let rejected = count(&["reject"]);
    let quarantined = count(&["quarantine"]);
    let values = [
        events.to_string(),
        accepted.to_string(),
        rejected.to_string(),
        quarantined.to_string(),
        (events - accepted - rejected - quarantined).to_string(),
        sum(rows, "suppressed").to_string(),
        sum(rows, "queued").to_string(),
        sum(rows, "duplicates").to_string(),
    ];
    row(&[
        l(stage, 11),
        r(&values[0], 9),
        r(rate, 7),
        r(&values[1], 9),
        r(&values[2], 9),
        r(&values[3], 11),
        r(&values[4], 7),
        r(&values[5], 10),
        r(&values[6], 9),
        r(&values[7], 10),
    ])
}

/// C# `TopView.Render`.
pub fn render(
    collector: &str,
    previous: Option<&Value>,
    current: &Value,
    elapsed_ms: i64,
    now: Timestamp,
) -> String {
    let current = Some(current);
    let has_previous = previous.is_some();
    let rate = |value: i64, before: i64| rate_text(value, before, has_previous, elapsed_ms);
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    let interval = if has_previous {
        format!("{} s", decimal((elapsed_ms + 50) / 100))
    } else {
        "-".to_owned()
    };
    line(format!(
        "bower top  {collector}  status {}  interval {interval}",
        text(current, "status")
    ));
    line(String::new());

    let intake = property(current, "intake");
    let attempts = number(intake, "attemptedRequests");
    line(format!(
        "Intake  attempts {attempts} ({}/s)  capacity refusals {}  privacy alert refusals {}",
        rate(
            attempts,
            number(property(previous, "intake"), "attemptedRequests")
        ),
        number(intake, "capacityRefusals"),
        number(intake, "privacyAlertRefusals")
    ));
    line(String::new());

    // Per stage, from the selection counters. The total row equals pipeline.eventsIn.
    let rows = array(property(current, "pipeline"), "rows");
    let previous_rows = array(property(previous, "pipeline"), "rows");
    line(row(&[
        l("STAGE", 11),
        r("EVENTS", 9),
        r("/S", 7),
        r("ACCEPTED", 9),
        r("REJECTED", 9),
        r("QUARANTINED", 11),
        r("OTHER", 7),
        r("SUPPRESSED", 10),
        r("QUEUED", 9),
        r("DUPLICATES", 10),
    ]));
    for stage in STAGE_ORDER {
        let stage_rows: Vec<&Value> = rows
            .iter()
            .copied()
            .filter(|row| text(Some(row), "stage") == stage)
            .collect();
        if !stage_rows.is_empty() {
            let before_rows: Vec<&Value> = previous_rows
                .iter()
                .copied()
                .filter(|row| text(Some(row), "stage") == stage)
                .collect();
            let events = sum(&stage_rows, "events");
            line(stage_row(
                stage,
                &stage_rows,
                events,
                &rate(events, sum(&before_rows, "events")),
            ));
        }
    }
    let total = number(property(current, "pipeline"), "eventsIn");
    line(stage_row(
        "total",
        &rows,
        total,
        &rate(total, number(property(previous, "pipeline"), "eventsIn")),
    ));
    line(String::new());

    line(row(&[
        l("STAGE", 11),
        l("POLICY", 32),
        l("ACTION", 18),
        r("EVENTS", 9),
        r("/S", 7),
    ]));
    for item in &rows {
        let item = Some(*item);
        let events = number(item, "events");
        let before: i64 = previous_rows
            .iter()
            .filter(|other| {
                let other = Some(**other);
                text(other, "stage") == text(item, "stage")
                    && text(other, "policyId") == text(item, "policyId")
                    && text(other, "action") == text(item, "action")
            })
            .map(|other| number(Some(other), "events"))
            .sum();
        line(row(&[
            l(text(item, "stage"), 11),
            l(text(item, "policyId"), 32),
            l(text(item, "action"), 18),
            r(&events.to_string(), 9),
            r(&rate(events, before), 7),
        ]));
    }

    line(String::new());
    line(row(&[
        l("SOURCE", 32),
        l("ENVIRONMENT", 18),
        r("EVENTS", 9),
        r("/S", 7),
    ]));
    let previous_sources = array(previous, "activity");
    for source in array(current, "activity") {
        let source = Some(source);
        let events = number(source, "eventCount");
        let before: i64 = previous_sources
            .iter()
            .filter(|other| {
                text(Some(other), "application") == text(source, "application")
                    && text(Some(other), "environment") == text(source, "environment")
            })
            .map(|other| number(Some(other), "eventCount"))
            .sum();
        line(row(&[
            l(text(source, "application"), 32),
            l(text(source, "environment"), 18),
            r(&events.to_string(), 9),
            r(&rate(events, before), 7),
        ]));
    }

    let listeners = array(current, "syslog");
    if !listeners.is_empty() {
        line(String::new());
        line(row(&[
            l("SYSLOG", 18),
            l("PROTOCOL", 8),
            r("FRAMES", 9),
            r("/S", 7),
            r("QUEUED", 9),
            r("REJECTED", 9),
            r("DROPPED", 8),
            r("MALFORMED", 9),
            r("OVERSIZED", 9),
            r("DENIED", 7),
            r("RECV ERRORS", 11),
            r("CONNS", 6),
        ]));
        let previous_listeners = array(previous, "syslog");
        for listener in listeners {
            let listener = Some(listener);
            let frames = number(listener, "framesReceived");
            let before: i64 = previous_listeners
                .iter()
                .filter(|other| text(Some(other), "id") == text(listener, "id"))
                .map(|other| number(Some(other), "framesReceived"))
                .sum();
            let values: Vec<String> = [
                "queued",
                "rejected",
                "dropped",
                "malformed",
                "oversized",
                "sendersDenied",
                "receiveErrors",
                "activeConnections",
            ]
            .iter()
            .map(|name| number(listener, name).to_string())
            .collect();
            line(row(&[
                l(text(listener, "id"), 18),
                l(text(listener, "protocol"), 8),
                r(&frames.to_string(), 9),
                r(&rate(frames, before), 7),
                r(&values[0], 9),
                r(&values[1], 9),
                r(&values[2], 8),
                r(&values[3], 9),
                r(&values[4], 9),
                r(&values[5], 7),
                r(&values[6], 11),
                r(&values[7], 6),
            ]));
        }
    }

    line(String::new());
    let queue = property(current, "queue");
    let oldest = property(queue, "oldestUndelivered")
        .and_then(Value::as_str)
        .and_then(bower_contracts::time::parse)
        .map_or_else(
            || "-".to_owned(),
            |at| {
                format!(
                    "{} s",
                    (now - at).num_milliseconds().div_euclid(1000).max(0)
                )
            },
        );
    line(format!(
        "Queue     queued {}  retrying {}  uploading {}  dead letters {}  undelivered bytes {}  oldest undelivered {oldest}",
        number(queue, "queued"),
        number(queue, "retrying"),
        number(queue, "uploading"),
        number(queue, "deadLettered"),
        number(queue, "undeliveredBytes")
    ));

    let delivery = property(current, "delivery").filter(|value| value.is_object());
    line(match delivery {
        Some(_) => {
            let latency = property(delivery, "latencyEwmaMilliseconds")
                .and_then(Value::as_i64)
                .map_or_else(|| "-".to_owned(), |value| format!("{value} ms"));
            format!(
                "Delivery  output {}  limit {} ({}-{})  in flight {}  latency {latency}  throttles {}  server errors {}  timeouts {}",
                text(delivery, "outputId"),
                number(delivery, "limit"),
                number(delivery, "minimumLimit"),
                number(delivery, "maximumLimit"),
                number(delivery, "inFlight"),
                number(delivery, "throttles"),
                number(delivery, "serverErrors"),
                number(delivery, "timeouts")
            )
        }
        None => "Delivery  -".to_owned(),
    });

    let tap = property(current, "tap").filter(|value| value.is_object());
    line(match tap {
        Some(_) => format!(
            "Tap       {}  sessions {}/{}  opened {}  refused {}  frames sent {}  dropped {}  rate limited {}",
            if property(tap, "enabled") == Some(&Value::Bool(true)) {
                "enabled"
            } else {
                "disabled"
            },
            number(tap, "activeSessions"),
            number(tap, "maximumSessions"),
            number(tap, "sessionsOpened"),
            number(tap, "sessionsRefused"),
            number(tap, "framesSent"),
            number(tap, "framesDropped"),
            number(tap, "framesRateLimited")
        ),
        None => "Tap       -".to_owned(),
    });
    out
}

/// C# `TryInteger`: `int.TryParse(NumberStyles.None)` within a range; absent is `fallback`.
fn integer(value: Option<&str>, fallback: i64, minimum: i64, maximum: i64) -> Option<i64> {
    match value {
        None => Some(fallback),
        Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => text
            .parse::<i32>()
            .ok()
            .map(i64::from)
            .filter(|value| (minimum..=maximum).contains(value)),
        Some(_) => None,
    }
}

fn authorize(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match std::env::var("BOWER_INGEST_TOKEN") {
        Ok(token) if !token.is_empty() => request.bearer_auth(token),
        _ => request,
    }
}

async fn status(client: &reqwest::Client, url: &reqwest::Url) -> CliResult<Value> {
    let response = authorize(client.get(url.clone()))
        .send()
        .await
        .map_err(|error| super::http_error(&error, HTTP_TIMEOUT))?;
    let code = response.status();
    if !code.is_success() {
        return Err(CliError(if code == reqwest::StatusCode::UNAUTHORIZED {
            "/v1/status returned HTTP 401: set BOWER_INGEST_TOKEN.".to_owned()
        } else {
            format!("/v1/status returned HTTP {}.", code.as_u16())
        }));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| super::http_error(&error, HTTP_TIMEOUT))?;
    serde_json::from_slice(&body).map_err(CliError::from_display)
}

pub fn run(args: &TopArgs) -> CliResult {
    let collector = args
        .collector
        .clone()
        .unwrap_or_else(|| DEFAULT_COLLECTOR.to_owned());
    let Some(interval) = integer(args.interval.as_deref(), 2, 1, 60) else {
        return Err(CliError::new(
            "--interval must be a whole number of seconds from 1 to 60.",
        ));
    };
    let iterations = match args.iterations.as_deref() {
        None => None,
        Some(value) => Some(
            integer(Some(value), 1, 1, i64::from(i32::MAX))
                .ok_or_else(|| CliError::new("--iterations must be a positive whole number."))?,
        ),
    };
    let base = reqwest::Url::parse(&ensure_slash(&collector)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let url = base.join("v1/status").map_err(CliError::from_display)?;
    let once = args.once;
    super::block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(CliError::from_display)?;
        let started = Instant::now();
        let mut previous: Option<(Value, i64)> = None;
        let mut sample: i64 = 0;
        loop {
            let current = status(&client, &url).await?;
            let at = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
            // --once samples twice, an interval apart, so rates are real.
            if !once || previous.is_some() {
                let view = render(
                    &collector,
                    previous.as_ref().map(|(value, _)| value),
                    &current,
                    at - previous.as_ref().map_or(0, |(_, at)| *at),
                    bower_contracts::time::now(),
                );
                let mut stdout = std::io::stdout();
                if !once && stdout.is_terminal() {
                    let _ = stdout.write_all(b"\x1b[H\x1b[2J");
                }
                let _ = stdout.write_all(view.as_bytes());
                let _ = stdout.flush();
                if once || iterations.is_some_and(|limit| sample + 1 >= limit) {
                    return Ok(0);
                }
            }
            previous = Some((current, at));
            sample += 1;
            tokio::time::sleep(Duration::from_secs(interval.unsigned_abs())).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_use_integer_tenths() {
        assert_eq!(rate_text(15, 0, true, 2000), "7.5");
        assert_eq!(rate_text(1, 0, true, 4000), "0.3");
        assert_eq!(rate_text(1, 2, true, 1000), "-");
        assert_eq!(rate_text(1, 0, false, 1000), "-");
    }

    /// Byte-identical to the C# `TopView` (TapHostTests.TopView_MatchesTheSharedSnapshot).
    #[test]
    fn render_matches_the_shared_snapshot() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/top");
        let read = |name: &str| std::fs::read_to_string(fixtures.join(name)).unwrap();
        let previous: Value = serde_json::from_str(&read("status-previous.json")).unwrap();
        let current: Value = serde_json::from_str(&read("status-current.json")).unwrap();
        let now = bower_contracts::time::parse("2026-07-26T02:14:19+00:00").unwrap();
        assert_eq!(
            render(
                "http://127.0.0.1:4319",
                Some(&previous),
                &current,
                2000,
                now
            ),
            read("expected.txt")
        );
        assert_eq!(
            render("http://127.0.0.1:4319", None, &current, 0, now),
            read("expected-first.txt")
        );
    }
}
