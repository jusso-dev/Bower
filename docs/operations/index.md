# Keep your security signal healthy

Start with the suggested fix in the console. Use these guides when you need to
investigate a specific part of the path.

| What you see | Start here |
| --- | --- |
| A machine has stopped reporting | [Fleet view](console-fleet.md) and [source silence](suppression-archive-and-source-silence.md) |
| Events are waiting in the queue | [Fleet and queue integrity](fleet-and-queue-integrity.md) |
| The test event is not found in Sentinel | [Doctor and DCR checks](doctor-and-dcr.md), then [evidence bundles](evidence-bundles.md) |
| A repeated event conflicts with an existing one | [Event identity conflicts](event-identity-conflicts.md) |
| You need to see a protected event moving through the collector | [Tap and top](tap-and-top.md) |
| A maintenance job needs attention | [Background jobs](background-jobs.md) |
| You need scripted management | [PowerShell](powershell.md) |

## Preserve the evidence

Do not delete queue files to clear a warning. Keep acknowledgement and cursor state
intact. Follow the recovery guidance in [queue durability](queue-v5-durability.md)
and [fleet and queue integrity](fleet-and-queue-integrity.md).

Console screenshots in these guides use synthetic preview data. A screenshot is
not evidence that your deployment has delivered an event.
