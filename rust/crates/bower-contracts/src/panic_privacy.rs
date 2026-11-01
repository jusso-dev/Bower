//! Suppress panic payloads while processing unredacted input.
//!
//! The host must retain this hook after its first installation. Installing another
//! process-wide panic hook later bypasses this protection.
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Once;

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}
static INSTALL: Once = Once::new();

/// Install the forwarding hook once, after any host hook and before worker threads.
pub fn install() {
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let sensitive = DEPTH.try_with(|depth| depth.get() != 0).unwrap_or(false);
            if !sensitive {
                previous(info);
            }
        }));
    });
}

/// Enter a synchronous sensitive operation after installing the process hook.
/// Nested calls are supported. The guard is not Send and must not span an await.
pub fn protect() -> Guard {
    install();
    DEPTH.with(|depth| depth.set(depth.get() + 1));
    Guard(PhantomData)
}

/// A thread-local sensitive-operation guard.
pub struct Guard(PhantomData<Rc<()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}
