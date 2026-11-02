# Replay-safe detections, first live run — 31 October 2026 (failed, retained)

**Strict result: failed.** Distinct-event delivery and incidents were correct, but two
detection keys raised a second alert on the catch-up path. This run is the reason the
rules now retry only in even catch-up slots; the fix was qualified by the
[second run](../ws2b-20261102-003156/README.md). Nothing here is relabelled as passed.

## What ran

- Azure subscription `945092a0-2500-4b25-85a4-99f1c3135906`, `australiaeast`, resource
  group `rg-bower-ws2-20261031-075516`, workspace `law-ws2` (Sentinel onboarded), table,
  DCE and DCR from `deploy/bicep/main.bicep`, ingestion by a certificate-authenticated app
  registration scoped to the DCR (Monitoring Metrics Publisher). No AWS resources.
- A local C# collector (macOS arm64, Release build of the branch, base `9d1bbcd`; hashes in
  [artifact-manifest.json](artifact-manifest.json)) with `BOWER_DELIVERY_LEASE_SECONDS=90`,
  `BOWER_DELIVERY_TIMEOUT_SECONDS=60`, delivering through the loopback fault proxy.
  Events entered through `/v1/events` with pack-shaped Windows 4625 and firewall-deny
  envelopes; some scenarios uploaded directly to the DCR stream (`method: direct`).
- Rules from `deploy/sentinel/analytics` with `frequencyMinutes=5` and
  `maxIngestionDelayMinutes=120` ([deployed rule settings](deployed-rules.json)).

## Results

[Final report](report-final.json) (10:44 UTC) and the [09:45 snapshot](report-0945.json):

| Scenario | Distinct / rows | Result |
| --- | --- | --- |
| a clean, a2 exact copies re-uploaded 83 min later | 37 / 74 | 1 incident per address, no new alert from the copies |
| b1 response dropped, network back | 37 / 49 (12 replayed after 88.0 s) | 1 incident per address |
| b2 collector killed mid-delivery | 37 / 74 (replayed after 90.5 s) | 1 incident per address |
| c response dropped at outage start, replay after 4,245.6 s | 37 / 74 | 1 incident per address, no alert from the replay |
| d1, d2, d3 originals delayed 2,402–4,249 s by a 4,241.7 s outage | 111 / 111 | each alerted once, on the first run after restoration |
| e beyond tolerance (150 min) and rewritten time (3 days) | 15 / 15 | no detection; monitor alerts grouped into 1 incident |
| f direct originals, f2 copies 78 min later | 37 / 74 | 1 incident per address |
| g crossing while both rules were disabled for 16.8 min | 37 / 37 | **2 alerts per key** (catch-up at 10:19 and 10:24), 1 incident per address |

Measured Sentinel behaviour: in a scheduled run `now()` equals the alert `EndTime`
exactly; the query executes about five minutes later; alerts became queryable in
`SecurityAlert` within 2.1 minutes; redeploying a rule can move its schedule. The
duplicate in g happened because a run's alerts have `TimeGenerated` after its own window
end, so the next run's look-back cannot see them.

Later scenarios started in this run (h, i, j, k, l, m) were not reported: the session
stopped on an API rate limit before evidence was collected. They are **not** evidence.

## Cleanup

[cleanup.json](cleanup.json) (2 November): resource group, tagged resources, workspace
(force-deleted; it had been left soft-deleted and was recovered only to purge it), the
application and its service principal (purged from deleted items) and role assignments
are all absent, each proven by an empty listing or an exact not-found code.
