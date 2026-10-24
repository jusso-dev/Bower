//! Manual timing probe for large values (the C# counterpart is tests/Bower.Benchmarks).
//!
//! `cargo test --release -p bower-redaction --test perf_probe -- --ignored --nocapture`

use std::time::Instant;

use bower_redaction::{PrivacyEngine, ScanText, default_value_detectors};

fn time(label: &str, engine: &PrivacyEngine, value: &str) {
    let json = format!("{{\"a\":\"{value}\"}}");
    let started = Instant::now();
    let result = engine.redact_json(&json);
    println!(
        "{label}: {} bytes, {:?}, ok={}, findings={}",
        json.len(),
        started.elapsed(),
        result.succeeded,
        result.findings.len()
    );
}

#[test]
#[ignore = "manual timing probe"]
fn large_values() {
    let engine = PrivacyEngine::with_default_policy();
    // Lazy statics (regex compilation, class tables) are not part of the measurement.
    time("warm-up", &engine, "\u{E9} 4111 1111 1111 1111 a@b.io");
    let n = 1_000_000 - 16;
    time("ascii", &engine, &"a ".repeat(n / 2));
    time("e-acute", &engine, &"\u{E9} ".repeat(n / 3));
    time("cjk", &engine, &"\u{5B57}".repeat(n / 3));
    time("mixed", &engine, &"word \u{E9} 123 ".repeat(n / 12));
    time("emoji", &engine, &"\u{1F600} ".repeat(n / 5));
    time(
        "mixed-digits",
        &engine,
        &"\u{5B57}\u{661} 4111 abc ".repeat(n / 16),
    );
    let dense: String = (0..20_000).map(|i| format!("u{i}@ex.io ")).collect();
    time("dense-emails", &engine, &dense);
    time("max-emails", &engine, &"a@b.io ".repeat(n / 7));

    let value = "\u{E9} ".repeat(n / 3);
    let scan = ScanText::new(&value);
    for detector in default_value_detectors() {
        let started = Instant::now();
        let mut matches = Vec::new();
        detector.detect(&scan, "$", &mut matches);
        println!("  {}: {:?}", detector.id(), started.elapsed());
    }
}

/// 32 custom detectors at the complexity limit over 1 MB values: the lazy DFA must hold
/// every pattern (no PikeVM fallback), so each detector stays in the tens of milliseconds.
#[test]
#[ignore = "manual timing probe"]
fn custom_detectors_at_the_complexity_limit() {
    let shapes = [
        r"(?:[^\n]?){511}x",
        r"(?:[^\n]|[^a]){256}",
        r"(?:[^\n][^a]){256}",
        r"(?:[^\n]{1,4}){128}",
        r"(?:[^\n]+){512}",
        r"(?:x|[^\n]{511})",
        r"[0-9A-Z_a-z]{20,512}",
        r"EMP-\d{6}",
    ];
    let mut yaml = String::from(
        "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: probe\n  version: 1.0.0\ncustomDetectors:\n",
    );
    for index in 0..32 {
        let pattern = shapes[index % shapes.len()];
        let sample = if pattern.starts_with("EMP") {
            "EMP-123456".to_owned()
        } else {
            "x".repeat(512)
        };
        yaml.push_str(&format!(
            "  - id: custom.p{index}\n    pattern: '{pattern}'\n    action: mask\n    tests:\n      match: ['{sample}']\n"
        ));
    }
    let policy = bower_redaction::load_privacy_profile(&yaml, None, None)
        .expect("probe profile loads")
        .policy;
    let value = "ab x".repeat(250_000);
    let scan = ScanText::new(&value);
    for detector in bower_redaction::value_detectors_for(&policy)
        .iter()
        .skip(default_value_detectors().len())
        .take(shapes.len())
    {
        let started = Instant::now();
        let mut matches = Vec::new();
        detector.detect(&scan, "$", &mut matches);
        println!(
            "  {}: {:?} ({} matches)",
            detector.id(),
            started.elapsed(),
            matches.len()
        );
    }
    let engine = PrivacyEngine::new(policy).expect("engine builds");
    time("warm-up", &engine, "EMP-123456");
    let n = 1_000_000 - 16;
    time("custom ascii", &engine, &"ab x".repeat(n / 4));
    time("custom words", &engine, &"word ab x. ".repeat(n / 11));
    time("custom emoji", &engine, &"\u{1F600} x".repeat(n / 6));
}
