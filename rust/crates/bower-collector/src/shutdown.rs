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
