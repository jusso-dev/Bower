//! Periodic `collector_health` records are C#-only (`src/Bower.Collector/CollectorHealthWorker.cs`).
//! The Rust collector must refuse the setting, never ignore it: alert rules would otherwise
//! report a running collector as stopped, or an operator would believe records are sent.

use bower_collector::CollectorSettings;

#[test]
fn health_record_interval_fails_closed() {
    let error = CollectorSettings::from_environment(|name| match name {
        "BOWER_COLLECTOR_ID" => Some("health-record-settings".into()),
        "BOWER_HEALTH_RECORD_INTERVAL_SECONDS" => Some("300".into()),
        _ => None,
    })
    .unwrap_err();
    assert!(
        error
            .message
            .contains("BOWER_HEALTH_RECORD_INTERVAL_SECONDS is supported only by the C# collector")
    );
    for off in [" ", "0"] {
        assert!(
            CollectorSettings::from_environment(|name| match name {
                "BOWER_COLLECTOR_ID" => Some("health-record-settings".into()),
                "BOWER_HEALTH_RECORD_INTERVAL_SECONDS" => Some(off.into()),
                _ => None,
            })
            .is_ok()
        );
    }
}
