//! Cooperative cancellation (C# `CancellationToken` / `ApplicationStopping`).

use tokio::sync::watch;

#[derive(Clone)]
pub struct ShutdownToken(watch::Receiver<bool>);

pub struct ShutdownTrigger(watch::Sender<bool>);

pub fn channel() -> (ShutdownTrigger, ShutdownToken) {
    let (sender, receiver) = watch::channel(false);
    (ShutdownTrigger(sender), ShutdownToken(receiver))
}

impl ShutdownTrigger {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub fn token(&self) -> ShutdownToken {
        ShutdownToken(self.0.subscribe())
    }
}

impl ShutdownToken {
    /// A token that is never cancelled.
    pub fn never() -> Self {
        let (sender, receiver) = watch::channel(false);
        // Keep the sender alive for the process lifetime so `cancelled` never resolves.
        std::mem::forget(sender);
        Self(receiver)
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once cancellation is requested (or the trigger is dropped).
    pub async fn cancelled(&self) {
        let mut receiver = self.0.clone();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }

    /// Sleeps for `duration`; returns `false` when cancelled first.
    pub async fn sleep(&self, duration: std::time::Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(duration) => true,
            () = self.cancelled() => false,
        }
    }
}

/// `IHostApplicationLifetime` for in-process requests to stop the host. A restart
/// request (C# `ManagedPrivacyProfileJob.RequestRestart`) stops the host gracefully and
/// makes the process exit with [`crate::managed_privacy::RESTART_EXIT_CODE`] so a
/// `Restart=on-failure` supervisor brings it back.
#[derive(Clone)]
pub struct ApplicationLifetime(std::sync::Arc<LifetimeState>);

struct LifetimeState {
    trigger: ShutdownTrigger,
    stopping: ShutdownToken,
    restart_requested: std::sync::atomic::AtomicBool,
    stop_calls: std::sync::atomic::AtomicUsize,
}

impl Default for ApplicationLifetime {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationLifetime {
    pub fn new() -> Self {
        let (trigger, stopping) = channel();
        Self(std::sync::Arc::new(LifetimeState {
            trigger,
            stopping,
            restart_requested: std::sync::atomic::AtomicBool::new(false),
            stop_calls: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// `StopApplication`: the host drains and stops as on SIGTERM.
    pub fn stop_application(&self) {
        self.0
            .stop_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.trigger.cancel();
    }

    /// Records that the supervisor must restart the process, then stops the host.
    pub fn request_restart(&self) {
        self.0
            .restart_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.stop_application();
    }

    /// True once a staged or cleared managed privacy profile asked for a restart.
    pub fn restart_requested(&self) -> bool {
        self.0
            .restart_requested
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Number of `stop_application` calls (test observability).
    pub fn stop_calls(&self) -> usize {
        self.0.stop_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Cancelled once a stop was requested (`ApplicationStopping`).
    pub fn stopping(&self) -> ShutdownToken {
        self.0.stopping.clone()
    }
}
