//! Port of tests/Bower.UnitTests/CanonicalIdentifierTokenTests.cs: structured number
//! detectors never claim a span wholly inside a canonical UUID or dashless GUID token, so
//! random producer event ids are not redacted (then quarantined as `event-id-redacted`),
//! while real identifiers in text still are.

use std::collections::HashSet;

use bower_redaction::checksum::is_valid_tfn;
use bower_redaction::identifier_tokens::{self, STRUCTURED_NUMBER_DETECTOR_IDS};
use bower_redaction::{
    DetectionMatch, PrivacyEngine, PrivacyPolicy, ScanText, default_value_detectors, detector_ids,
    load_privacy_profile,
};
use serde_json::Value;

const SAMPLES: usize = 200_000;

// First group passes the TFN checksum.
const TFN_FIRST_GROUP_UUID: &str = "10040680-c19c-4eec-8ca0-056e33f7f420";

fn opt_in() -> PrivacyPolicy {
    PrivacyPolicy {
        enabled_opt_in_detectors: [
            detector_ids::IP_ADDRESS,
            detector_ids::HOSTNAME,
            detector_ids::USERNAME,
            detector_ids::ADDRESS,
            detector_ids::GPS,
            detector_ids::SECURITY_MARKING,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<HashSet<_>>(),
        ..PrivacyPolicy::create_default()
    }
}

fn engines() -> [PrivacyEngine; 2] {
    [
        PrivacyEngine::with_default_policy(),
        PrivacyEngine::new(opt_in()).unwrap(),
    ]
}

/// SplitMix64: deterministic test ids without a new dependency.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.next().to_be_bytes());
        bytes[8..].copy_from_slice(&self.next().to_be_bytes());
        bytes
    }
}

/// Random version 4 ids, and version 7 ids from 2024-08 to 2025-12 whose first group is all digits.
fn identifier(random: &mut Random, shape: &str) -> String {
    let mut bytes = random.bytes();
    if shape == "v7-digits" {
        const FROM: u64 = 1_722_470_400_000; // 2024-08-01T00:00:00Z
        const TO: u64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z
        loop {
            let milliseconds = FROM + random.next() % (TO - FROM);
            bytes[..6].copy_from_slice(&milliseconds.to_be_bytes()[2..]);
            if hex::encode(&bytes[..4])
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            {
                break;
            }
            bytes = random.bytes();
        }
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
    } else {
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
    }
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = hex::encode(bytes);
    let dashed = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    match shape {
        "dashed" | "v7-digits" => dashed,
        "dashed-upper" => dashed.to_ascii_uppercase(),
        "dashless" => hex,
        "dashless-upper" => hex.to_ascii_uppercase(),
        "braced" => format!("{{{dashed}}}"),
        _ => unreachable!("{shape}"),
    }
}

fn structured_matches(text: &str) -> Vec<DetectionMatch> {
    let scan = ScanText::new(text);
    let mut matches = Vec::new();
    for detector in default_value_detectors() {
        if STRUCTURED_NUMBER_DETECTOR_IDS.contains(&detector.id()) {
            detector.detect(&scan, "$", &mut matches);
        }
    }
    matches
}

fn altered(engine: &PrivacyEngine, json: &str, id: &str) -> usize {
    let result = engine.redact_json(json);
    assert!(result.succeeded);
    usize::from(!result.findings.is_empty() || !result.redacted_json.unwrap().contains(id))
}

fn redacted_event_id(engine: &PrivacyEngine, value: &str) -> String {
    let json = serde_json::json!({ "eventId": value }).to_string();
    let redacted: Value =
        serde_json::from_str(&engine.redact_json(&json).redacted_json.unwrap()).unwrap();
    redacted["eventId"].as_str().unwrap().to_owned()
}

/// 200,000 ids per shape, each as a root `eventId` (default policy) and, for every tenth,
/// in free text and under the opt-in policy.
fn assert_never_altered(shape: &str) {
    let [defaults, opt_in] = engines();
    let mut random = Random(20_261_107);
    let mut raw_detector_hits = 0;
    let mut changed = 0;
    for sample in 0..SAMPLES {
        let id = identifier(&mut random, shape);
        raw_detector_hits += structured_matches(&id).len();
        let event = format!(r#"{{"eventId":"{id}"}}"#);
        changed += altered(&defaults, &event, &id);
        if sample % 10 == 0 {
            let text = format!(
                r#"{{"message":"request {id} failed (ref={id}); retry \"{id}\"","ids":["{id}"]}}"#
            );
            changed += altered(&opt_in, &event, &id)
                + altered(&defaults, &text, &id)
                + altered(&opt_in, &text, &id);
        }
    }
    // The corpus exercises the defect: the detectors alone still fire on these ids.
    assert!(
        raw_detector_hits > 50,
        "{shape}: only {raw_detector_hits} raw detector hits"
    );
    assert_eq!(changed, 0, "{shape}");
}

#[test]
fn random_v4_dashed_ids_are_never_altered() {
    assert_never_altered("dashed");
}

#[test]
fn random_v4_dashed_uppercase_ids_are_never_altered() {
    assert_never_altered("dashed-upper");
}

#[test]
fn random_v4_dashless_ids_are_never_altered() {
    assert_never_altered("dashless");
}

#[test]
fn random_v4_dashless_uppercase_ids_are_never_altered() {
    assert_never_altered("dashless-upper");
}

#[test]
fn random_v4_braced_ids_are_never_altered() {
    assert_never_altered("braced");
}

#[test]
fn v7_ids_with_all_digit_first_groups_are_never_altered() {
    assert_never_altered("v7-digits");
}

// ABNs are public business numbers and allowed by default, so they are not listed.
const REAL_IDENTIFIERS: &[&str] = &[
    "123456782",
    "123 456 782",
    "123-456-782",
    "10040680",
    "000 000 019",
    "2123456701",
    "2123 45670 1",
    "8003600000000007",
    "4111111111111111",
    "4111 1111 1111 1111",
    "4111-1111-1111-1111",
    "5555555555554444",
    "378282246310005",
    "GB82WEST12345698765432",
    "gb82west12345698765432",
    "DE89370400440532013000",
    "NL91ABNA0417164300",
    "FR1420041010050500013M02606",
];

// Contexts a real identifier is written in, including next to UUID-like fragments.
const CONTEXTS: &[&str] = &[
    "{0}",
    "value {0} end",
    "TFN {0}",
    "TFN:{0}",
    "x-{0}",
    "{0}-x",
    "-{0}-",
    "\\\"{0}\\\"",
    "'{0}'",
    "({0})",
    "[{0}]",
    "{{0}}",
    "<{0}>",
    "id={0};",
    "{0}.",
    ",{0},",
    "/{0}/",
    "ref:{0}",
    "{0}\\n",
    "#{0}",
    "{0}-c19c-4eec-8ca0",
    "{0}-c19c-4eec-8ca0-056e33f7f420-0",
    "c19c-{0}",
    "{0} c19c-4eec-8ca0-056e33f7f420",
    "urn:uuid:{0}",
    "3f2a9c1e-c19c-4eec-8ca0-056e33f7f420 {0}",
    "{0}/3f2a9c1e-c19c-4eec-8ca0-056e33f7f420",
];

#[test]
fn real_identifiers_in_text_and_next_to_punctuation_are_still_redacted() {
    let engines = engines();
    for identifier in REAL_IDENTIFIERS {
        assert!(
            structured_matches(identifier)
                .iter()
                .any(|found| found.validated && found.end - found.start == identifier.len()),
            "{identifier}"
        );
        for engine in &engines {
            for context in CONTEXTS {
                let text = context.replace("{0}", identifier);
                let result =
                    engine.redact_json(&format!(r#"{{"eventId":"{text}","message":"{text}"}}"#));
                assert!(result.succeeded, "{text}");
                assert!(
                    !result.redacted_json.unwrap().contains(identifier),
                    "{text}"
                );
            }
        }
    }
}

#[test]
fn near_canonical_shapes_get_no_exemption() {
    let engine = PrivacyEngine::with_default_policy();
    for value in [
        "TFN-10040680-c19c-4eec-8ca0-056e33f7f420",
        "10040680-c19c-4eec-8ca0-056e33f7f420x",
        "10040680-c19c-4eec-8ca0-056e33f7f4200",
        "10040680-c19c-4eec-8ca0-056e33f7f42",
        "10040680-c19c-4eec-8ca0-056e33f7f42g",
        "10040680-c19c-4eec-8ca0_056e33f7f420",
        "10040680-c19c4eec-8ca0-056e33f7f420",
        "10040680 c19c-4eec-8ca0-056e33f7f420",
        "10040680-c19c-4eec-8ca0-056e33f7f420_",
        "a-10040680-c19c-4eec-8ca0-056e33f7f420",
        "4111111111111111-c19c-4eec-8ca0-056e33f7f420",
        "123456782-c19c-4eec-8ca0-056e33f7f420",
    ] {
        assert!(identifier_tokens::find(value).is_empty(), "{value}");
        assert_ne!(redacted_event_id(&engine, value), value);
    }
}

/// Accepted limit, documented in docs/privacy/privacy-secret-engine.md: a producer that
/// deliberately writes an eight-digit TFN as the first group of a UUID is not caught.
#[test]
fn attacker_chosen_uuid_with_tfn_first_group_is_an_identifier_not_a_tfn() {
    assert!(is_valid_tfn("10040680"));
    let engine = PrivacyEngine::with_default_policy();
    for id in [
        "10040680-0000-0000-0000-000000000000".to_owned(),
        TFN_FIRST_GROUP_UUID.to_owned(),
        format!("{{{TFN_FIRST_GROUP_UUID}}}"),
    ] {
        assert_eq!(redacted_event_id(&engine, &id), id);
    }
    // The same eight digits anywhere else are still a TFN.
    assert!(
        !engine
            .redact_json(r#"{"note":"TFN 10040680 c19c"}"#)
            .redacted_json
            .unwrap()
            .contains("10040680")
    );
}

#[test]
fn secret_and_custom_detectors_still_scan_identifier_tokens() {
    let guid = "dd97c1d25d12d2e202c1e010d70d55f4";
    assert!(
        !PrivacyEngine::with_default_policy()
            .redact_json(&format!(r#"{{"note":"datadog api_key {guid}"}}"#))
            .redacted_json
            .unwrap()
            .contains(guid)
    );
    let policy = load_privacy_profile(
        "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: uuid-test\n  version: 1.0.0\n\
         customDetectors:\n  - id: custom.uuid\n    pattern: '[0-9a-f]{8}-[0-9a-f]{4}'\n    action: mask\n\
         \x20   tests:\n      match: ['10040680-c19c']\n",
        Some(&[0u8; 32]),
        Some("k1"),
    )
    .unwrap()
    .policy;
    assert_ne!(
        redacted_event_id(&PrivacyEngine::new(policy).unwrap(), TFN_FIRST_GROUP_UUID),
        TFN_FIRST_GROUP_UUID
    );
}

#[test]
fn find_returns_bounded_tokens_only() {
    // Byte offsets: `é` is two UTF-8 bytes (one UTF-16 unit in C#, so C# reports 76..112).
    let text = format!(
        "a {TFN_FIRST_GROUP_UUID}, {{DD97C1D25D12D2E202C1E010D70D55F4}} é{TFN_FIRST_GROUP_UUID} x{TFN_FIRST_GROUP_UUID}"
    );
    assert_eq!(
        identifier_tokens::find(&text),
        vec![(2, 38), (41, 73), (77, 113)]
    );
    for (token, expected) in [
        ("10040680-c19c-4eec-8ca0-056e33f7f42-", false),
        ("dd97c1d25d12d2e202c1e010d70d55f", false),
        ("GB82WEST12345698765432aaaaaaaaaa", false),
        ("00000000-0000-0000-0000-000000000000", true),
    ] {
        assert_eq!(
            identifier_tokens::is_canonical_identifier(token),
            expected,
            "{token}"
        );
    }
    assert!(!identifier_tokens::applies_to(detector_ids::PAY_ID));
    assert!(!identifier_tokens::applies_to(detector_ids::API_KEY));
}
