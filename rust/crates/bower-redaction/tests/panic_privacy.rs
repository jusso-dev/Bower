use std::process::Command;
use std::sync::{Arc, Barrier};

use bower_redaction::{
    DetectionMatch, PrivacyEngine, PrivacyPolicy, ScanText, SensitiveDetector,
    default_field_name_detector,
};

struct PanickingDetector(Arc<Barrier>);

impl SensitiveDetector for PanickingDetector {
    fn id(&self) -> &str {
        "custom.panic"
    }
    fn category(&self) -> &str {
        "custom"
    }
    fn detect(&self, _: &ScanText<'_>, _: &str, _: &mut Vec<DetectionMatch>) {
        self.0.wait();
        panic!("sensitive-panic-payload-8274");
    }
}

#[test]
fn redaction_suppresses_sensitive_panic_and_preserves_concurrent_panic_reporting() {
    const CHILD: &str = "BOWER_PANIC_PRIVACY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let barrier = Arc::new(Barrier::new(2));
        let engine = PrivacyEngine::with_detectors(
            PrivacyPolicy::default(),
            vec![Box::new(PanickingDetector(Arc::clone(&barrier)))],
            default_field_name_detector(),
        )
        .unwrap();
        let unrelated = std::thread::spawn(move || {
            barrier.wait();
            panic!("unrelated-panic-marker-1936");
        });
        assert!(!engine.redact_json(r#"{"message":"sensitive"}"#).succeeded);
        assert!(unrelated.join().is_err());
        let text_engine = PrivacyEngine::with_detectors(
            PrivacyPolicy::default(),
            vec![Box::new(PanickingDetector(Arc::new(Barrier::new(1))))],
            default_field_name_detector(),
        )
        .unwrap();
        assert!(!text_engine.redact_text("sensitive").succeeded);
        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "redaction_suppresses_sensitive_panic_and_preserves_concurrent_panic_reporting",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("sensitive-panic-payload-8274"), "{stderr}");
    assert!(stderr.contains("unrelated-panic-marker-1936"), "{stderr}");
}
