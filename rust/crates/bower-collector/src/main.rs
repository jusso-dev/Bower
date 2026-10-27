//! `bower-collector` entry point. Composition lives in `bower_collector::host`.

use std::process::ExitCode;

use bower_collector::host::{self, BuildOptions};
use bower_collector::{
    CollectorSettings, HostError, bundle, credential, logging, managed_privacy, server, shutdown,
};
use tracing::info;

fn main() -> ExitCode {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--healthcheck")
    {
        let listen =
            std::env::var("BOWER_LISTEN_URL").unwrap_or_else(|_| "http://127.0.0.1:4319".into());
        return if server::healthcheck(&listen) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Bower collector failed: IOException: {}", error.kind());
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        // Non-zero when the host asked the supervisor for a restart (managed privacy
        // profile staged or cleared), so Restart=on-failure also applies it.
        Ok(true) => ExitCode::from(managed_privacy::RESTART_EXIT_CODE),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            // Exit with a status code so a supervisor restarts the process. Messages are
            // Bower-authored configuration or storage errors; no secrets.
            eprintln!("Bower collector failed: {}: {}", error.kind, error.message);
            ExitCode::FAILURE
        }
    }
}

/// `Ok(true)` when a restart was requested.
async fn run() -> Result<bool, HostError> {
    logging::init();
    let settings = CollectorSettings::from_process_environment()?;
    let bundle = bundle::load(&settings)?;
    let credential = credential::create(&settings);
    let output = host::create_output(&settings, credential.clone())?;
    // Token enrolment: the host builds the key-bound management credential itself.
    let management_credential = credential
        .filter(|_| !settings.uses_enrolment())
        .map(credential::management_source);
    let listen_url = settings.listen_url.clone();
    let mut collector = host::build(
        settings,
        bundle,
        BuildOptions {
            output,
            credential: management_credential,
            ..BuildOptions::default()
        },
    )?;
    collector.initialize().await?;

    let listeners = server::bind(&server::listen_addresses(&listen_url)?).await?;
    let (trigger, token) = shutdown::channel();
    tokio::spawn(async move {
        wait_for_signal().await;
        info!("Shutdown requested; draining.");
        trigger.cancel();
    });
    info!(listen_url, "Bower collector listening.");
    let lifetime = collector.lifetime();
    collector.run(listeners, token).await;
    info!("Bower collector stopped.");
    Ok(lifetime.restart_requested())
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
