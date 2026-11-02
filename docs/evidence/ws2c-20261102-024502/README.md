# Review-fix validation — 2 November 2026

**Result: passed (targeted validation, not a full campaign).** A short live check of the
PR #169 review fixes in a real Sentinel workspace (run `bower-ws2c-20261102-024502`, `australiaeast`,
resource group `rg-bower-ws2c-20261102-024502`, workspace `law-ws2c`, table and DCR from
`deploy/bicep/main.bicep`). Rows were uploaded directly to the DCR stream (`method:
direct`, collector id `ws2c-direct`); no collector, no AWS. The full replay campaign is
[ws2b-20261102-003156](../ws2b-20261102-003156/README.md).

| Check | Result |
| --- | --- |
| Catch-up guard: `frequencyMinutes=30`, `catchUpMinutes=60` | deployment validation fails with the `catchUpMinutes must be at least (alertVisibilityRuns + 1) x frequencyMinutes` message ([output](catch-up-guard-validation.txt)) |
| Default deployment (`maxIngestionDelayMinutes=120`) | succeeded: both functions and all three rules, so Sentinel accepted every rule query ([deployment](deployment.json)) |
| `BowerSecurityEventsOfType` vs `BowerSecurityEvents` on 12 events uploaded twice | 12 rows each, `BowerCopies` sum 24 each, same first ingestion and event time for all 12, no `RawEnvelope` column, 0 rows for another type ([result](typed-vs-full.json)) |
| Replay more than two days after its event time | original (event time 47 h 52 min old) kept `TimeGenerated`; the identical replay 10 min later had `TimeGenerated` rewritten while `RawEnvelope.timeGenerated` kept the original ([rows](rows.json)) |
| Monitor, slot holding the originals (`now()` = 03:00) | 5 late events: the 3 originals and 2 three-day-old events without an original ([result](monitor-new-03.json)) |
| Monitor, slot holding the replays (`now()` = 04:00) | no rows: replays are excluded ([result](monitor-new-04.json)); the same query without the earlier-copy check reports the 3 replays as late ([result](monitor-without-replay-check-04.json)) |
| Previous monitor (two-run look-back) at `now()` = 04:00 | reports the 5 events from the earlier hour again: the double-reporting the fix removes ([result](monitor-old-04.json)) |
| Brute-force rule live with the new spacing and typed function | 1 `owned-window` alert for the 12-event crossing; no second alert in the following three runs (through the run executed at 03:23 UTC), including retry slot 2 ([alerts](alerts.json)) |

Monitor queries were run through the Log Analytics query API with `now()` replaced by the
stated instant and `maxDelay` set to 120 minutes; the live monitor rule's first hourly
slot with data was after the time box, so its scheduled run is **not** evidence.

## Cleanup

[cleanup.json](cleanup.json): 9/9 absent (resource group, tagged resources, force-deleted
workspace, no soft-deleted copy, application, service principal, both purged from deleted
items, role assignments), each by an empty listing or an exact not-found code.
