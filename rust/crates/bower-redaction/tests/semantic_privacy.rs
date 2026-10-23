use bower_redaction::PrivacyEngine;

#[test]
fn cloud_direction_only_allows_fixed_new_value_enum() {
    let engine = PrivacyEngine::with_default_policy();
    for event_type in ["aws_cloudtrail", "gcp_cloud_audit"] {
        for direction in ["grant", "revoke", "mixed", "replace", "unknown"] {
            let json = format!(
                r#"{{"eventType":"{event_type}","change":{{"field":"permission_direction","previousValue":"before-canary","newValue":"{direction}"}}}}"#
            );
            let result = engine.redact_json(&json);
            assert!(result.succeeded);
            let text = result.redacted_json.unwrap();
            assert!(!text.contains("canary"));
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["change"]["newValue"], direction);
        }
        for value in [
            r#""after-canary""#,
            r#"{"grant":"after-canary"}"#,
            r#"["after-canary"]"#,
        ] {
            let json = format!(
                r#"{{"eventType":"{event_type}","change":{{"field":"permission_direction","newValue":{value}}}}}"#
            );
            let result = engine.redact_json(&json);
            let text = result.redacted_json.unwrap();
            assert!(!text.contains("newValue"));
            assert!(!text.contains("canary"));
        }
    }
}

#[test]
fn cloud_direction_bytes_match_csharp_fixture() {
    let input = r#"{"eventType":"gcp_cloud_audit","change":{"field":"permission_direction","newValue":"mixed"},"attributes":{"cloud.permissionChanges":{"entries":[{"member":"allUsers","permission":"roles/viewer","direction":"grant"}]}}}"#;
    assert_eq!(
        PrivacyEngine::with_default_policy()
            .redact_json(input)
            .redacted_json
            .as_deref(),
        Some(input)
    );
    for input in [
        r#"{"eventType":"other","change":{"field":"permission_direction","newValue":"grant"}}"#,
        r#"{"eventType":"aws_cloudtrail","change":{"field":"password","newValue":"grant"}}"#,
    ] {
        assert!(
            !PrivacyEngine::with_default_policy()
                .redact_json(input)
                .redacted_json
                .unwrap()
                .contains("newValue")
        );
    }
}

#[test]
fn unapproved_change_values_are_removed_regardless_of_shape() {
    for field in ["password", "apiKey", "access_token", "unknown", "role"] {
        let json = format!(
            r#"{{"change":{{"field":"{field}","previousValue":{{"nested":"before-canary"}},"newValue":["after-canary"]}}}}"#
        );
        let result = PrivacyEngine::with_default_policy().redact_json(&json);
        assert!(result.succeeded);
        assert!(!result.redacted_json.unwrap().contains("canary"));
        assert_eq!(
            result.removed_paths,
            ["$.change.previousValue", "$.change.newValue"]
        );
    }
}

#[test]
fn reviewed_role_change_keeps_values_and_still_runs_detectors() {
    let engine = PrivacyEngine::with_default_policy();
    let result = engine.redact_json(r#"{"eventType":"role_membership_changed","change":{"field":"role","previousValue":"reader","newValue":"admin"}}"#);
    assert!(result.succeeded);
    let text = result.redacted_json.unwrap();
    assert!(text.contains(r#""previousValue":"reader""#));
    assert!(text.contains(r#""newValue":"admin""#));
    let result = engine.redact_json(r#"{"eventType":"role_membership_changed","change":{"field":"role","newValue":"4111111111111111"}}"#);
    assert!(!result.redacted_json.unwrap().contains("4111111111111111"));
}

#[test]
fn request_urls_discard_credentials_and_opaque_query_values() {
    for (path, expected) in [
        ("/login?opaque=query-canary#fragment-canary", "/login"),
        (
            "https://user:userinfo-canary@example.test/login?code=query-canary",
            "https://example.test/login",
        ),
        (
            "//user:userinfo-canary@example.test/login#fragment-canary",
            "//example.test/login",
        ),
        (
            "https://user:password-canary?opaque=x@host/login",
            "[redacted]",
        ),
        ("/login%3Ftoken=query-canary", "/login"),
        (
            "https://user%40userinfo-canary@example.test/login",
            "[redacted]",
        ),
        ("https:\\userinfo-canary", "[redacted]"),
    ] {
        let json = serde_json::json!({"request":{"path":path}}).to_string();
        let result = PrivacyEngine::with_default_policy().redact_json(&json);
        assert!(result.succeeded);
        let text = result.redacted_json.unwrap();
        assert!(!text.contains("canary"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["request"]["path"], expected);
    }
}

#[test]
fn semantic_guard_bytes_match_csharp_fixture() {
    let input = r#"{"change":{"field":"password","newValue":"after-canary"},"request":{"path":"/login?opaque=query-canary"}}"#;
    // Exact output asserted by C# SemanticPrivacyTests.SemanticGuardBytesMatchRustFixture.
    let expected = r#"{"change":{"field":"password"},"request":{"path":"/login"},"privacy":{"detected":["field-name-secret"],"actions":{"field-name-secret":"Removed"}}}"#;
    assert_eq!(
        PrivacyEngine::with_default_policy()
            .redact_json(input)
            .redacted_json
            .as_deref(),
        Some(expected)
    );
}
