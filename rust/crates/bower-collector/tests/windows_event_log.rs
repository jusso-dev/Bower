//! The Windows Event Log source (`src/Bower.Source.WindowsEventLog`) is C#-only: the Rust
//! collector does not target Windows. It must refuse the setting, never ignore it.

use bower_collector::CollectorSettings;

/// The Windows Event Log source is C#-only; configuring it on the Rust collector stops
/// start-up instead of silently collecting nothing.
#[test]
fn windows_event_log_config_fails_closed() {
    let error = CollectorSettings::from_environment(|name| match name {
        "BOWER_COLLECTOR_ID" => Some("windows-eventlog-settings".into()),
        "BOWER_WINDOWS_EVENTLOG_CONFIG" => {
            Some("C:/ProgramData/Bower/windows-eventlog.json".into())
        }
        _ => None,
    })
    .unwrap_err();
    assert!(error.message.contains(
        "BOWER_WINDOWS_EVENTLOG_CONFIG is supported only by the C# collector on Windows"
    ));
    assert!(
        CollectorSettings::from_environment(|name| match name {
            "BOWER_COLLECTOR_ID" => Some("windows-eventlog-settings".into()),
            "BOWER_WINDOWS_EVENTLOG_CONFIG" => Some(" ".into()),
            _ => None,
        })
        .is_ok()
    );
}
