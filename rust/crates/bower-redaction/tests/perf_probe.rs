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
