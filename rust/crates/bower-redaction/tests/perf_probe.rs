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

/// 32 custom detectors at the complexity limit over values at the scan limit: the lazy DFA must hold
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
    // Values at the custom detector scan limit (longer values quarantine).
    let n = bower_redaction::detectors::custom::MAXIMUM_SCANNED_LENGTH;
    time("custom ascii", &engine, &"ab x".repeat(n / 4));
    time("custom words", &engine, &"word ab x. ".repeat(n / 11));
    time("custom emoji", &engine, &"\u{1F600} x".repeat(n / 6));
}

/// Council A2 probes (mirrors the C# measurements in the engine notes): quadratic and long
/// single-match patterns at doubling value lengths up to the payload limit, and a
/// 32-detector profile. Each event must finish quickly or quarantine deterministically.
#[test]
#[ignore = "manual timing probe"]
fn custom_detector_work_is_bounded() {
    let header = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\ncustomDetectors:\n";
    let detector = |index: usize, pattern: &str, sample: &str| {
        format!(
            "  - id: custom.p{index}\n    pattern: '{pattern}'\n    action: mask\n    tests:\n      match: ['{sample}']\n"
        )
    };
    let mixed: String = (0..32)
        .map(|index| {
            let (pattern, sample) = [
                ("a+z|a", "a"),
                ("token=.+", "token=x"),
                (".+x.+", "axb"),
                ("x[^a]{3}", "xbcd"),
            ][index % 4];
            detector(index, pattern, sample)
        })
        .collect();
    type Make = fn(usize) -> String;
    let probes: [(&str, Make, String); 5] = [
        (
            "a+z|a",
            |n| "a".repeat(n),
            format!("{header}{}", detector(0, "a+z|a", "a")),
        ),
        (
            "token=.+",
            |n| format!("token={}", "x".repeat(n)),
            format!("{header}{}", detector(0, "token=.+", "token=x")),
        ),
        (
            ".+x.+",
            |n| "x".repeat(n),
            format!("{header}{}", detector(0, ".+x.+", "axb")),
        ),
        (
            "token=a x",
            |n| "token=a ".repeat(n / 8),
            format!("{header}{}", detector(0, "token=.+", "token=x")),
        ),
        (
            "32 mixed",
            |n| "ab x".repeat(n / 4),
            format!("{header}{mixed}"),
        ),
    ];
    for (name, make, yaml) in probes {
        let policy = bower_redaction::load_privacy_profile(&yaml, None, None)
            .expect("probe profile loads")
            .policy;
        let engine = PrivacyEngine::new(policy).expect("engine builds");
        for n in [1024, 4096, 16_384, 32_768, 65_536, 131_072, 1_000_000] {
            let json = format!("{{\"v\":\"{}\"}}", make(n));
            let mut times = Vec::new();
            let mut outcomes = Vec::new();
            for _ in 0..3 {
                let started = Instant::now();
                let result = engine.redact_json(&json);
                times.push(format!("{:.0}", started.elapsed().as_secs_f64() * 1000.0));
                let outcome = if result.succeeded {
                    "ok".to_owned()
                } else {
                    result.failure_code.unwrap_or_default()
                };
                if !outcomes.contains(&outcome) {
                    outcomes.push(outcome);
                }
            }
            println!(
                "{name:<10} n={n:>7}  ms=[{}]  {outcomes:?}",
                times.join(" ")
            );
        }
    }
}
