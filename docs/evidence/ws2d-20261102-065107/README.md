# Council-fix query validation — 2 November 2026

**Result: passed (targeted query validation, not a campaign; rules disabled).** A short
live check of the PR #169 council round 1 content in a real Sentinel workspace (run
`bower-ws2d-20261102-065107`, `australiaeast`, resource group
`rg-bower-ws2d-20261102-065107`, table and DCR from `deploy/bicep/main.bicep`). Rows were
uploaded directly to the DCR stream (`method: direct`); no collector, no AWS. Rule
queries were run through the Log Analytics query API with `now()` replaced by the stated
instant and `maxDelay` set to 120 minutes. No scheduled rule ran, so this is **not**
evidence of scheduled alerting, the catch-up path in a real run, or the monitor.

| Check | Result |
| --- | --- |
| Default deployment (`maxIngestionDelayMinutes=120`, `PT205M` look-back) | succeeded: both functions and all three rules, so Sentinel accepted every rule query ([deployment](deployment.json)) |
| Second deployment beside it, `detectionKeyScope=second` | succeeded: six rules side by side, the second set with ` [second]` display names ([output](deployment-second-scope.txt)) |
| Pre-aggregated rules vs full ranking, both rules, 6 instants each | identical output at every instant ([results](rules-check.json)) |
| Fixed grid, crossing first ingested 06:59:17 | `now()` 07:05:00, 07:07:30 and 07:09:59 all give `owned-window` (window 06:55–07:00); 07:10:00 gives nothing (slot 1); 07:15:00 and 07:17:31 give `catch-up-2` ([results](rules-check.json)) |
| Below-threshold bucket | never returned by either rule ([results](rules-check.json)) |
| `BowerSecurityEventsOfType` vs `BowerSecurityEvents` | authentication 17 of 17 and denials 43 of 43 identities with the same first copy and copy count; one identity differs, see below ([result](typed-vs-canonical.json)) |
| Event id reused with a changed type (`ws2-q-below-deny-0000-b48f00b6f16e`: denial first, authentication later) | head typed function: 0 authentication rows and 2 denial copies, as the canonical function; the previous filter-first version: 1 authentication row and 1 denial copy ([result](typed-reuse.json), [rows](reuse-rows.json)) |

The one differing identity, `ws2-q-cross-deny-0000-087d2939cde4`, has two rows of
different types with the **same** `ingestion_time()` (one upload batch), so
`arg_min` has no single first copy and the two functions picked different rows. That is
the exact-tie limit in the guide's known limits, not a collapse difference. The two
`typed rows differing from canonical` counts in [typed-reuse.json](typed-reuse.json)
(18 and 44) come from a flawed check (a full outer join comparing nulls) and are
superseded by [typed-vs-canonical.json](typed-vs-canonical.json).

The first typed-function draft read `ingestion_time()` after its semi-join, where it is
null; this run found it, and the shipped function reads it before the join (covered by
a content test).

## Cleanup

[cleanup.json](cleanup.json): 9/9 absent (resource group, tagged resources, force-deleted
workspace, no soft-deleted copy, application, service principal, both purged from deleted
items, role assignments), each by an empty listing or an exact not-found code.
