# Rust redaction panic reporting

Rust invokes the panic hook before `catch_unwind`, so catching a redaction
failure alone does not keep panic payloads out of logs. Bower installs a
process-wide forwarding hook and marks synchronous operations handling raw
input as sensitive on the current thread. The hook suppresses those panic
reports and forwards unrelated panics to the hook that was installed before it.
Redaction still fails closed; no raw payload is persisted by that failure.

The supported collector and Lambda binaries install Bower's hook at startup.
An application embedding the Rust libraries must call
`bower_contracts::panic_privacy::install()` after configuring its own hook and
before starting worker threads, then keep Bower's hook installed for the
process lifetime. Redaction also installs it lazily if needed. Installing or
replacing a panic hook afterwards bypasses this safeguard; process-global hooks
cannot be protected from arbitrary code running inside the process. Hooks must
not be changed concurrently with installation. A protected operation must not
move its guard across threads or await while holding it; spawned work that handles
raw input needs its own guard.

The subprocess test `panic_privacy` checks suppression of a detector panic and
forwarding of a simultaneous unrelated thread's panic. Other tests verify the
redaction failure remains retryable and does not persist an event.
