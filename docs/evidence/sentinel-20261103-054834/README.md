# Final replay-safe content as scheduled rules — 3 November 2026

**Strict result: passed, with tooling defects found and fixed.** The analytics content on
`main` (commit `5b7ded8`; [`deploy/sentinel/analytics`](../../../deploy/sentinel/analytics/main.bicep)
unchanged since `d7ddc55`, [hashes](artifact-manifest.json)) ran as **real enabled
scheduled rules** with the template defaults. No `now()` was substituted for any result
below unless stated. The verifier passed 42 of 42 checks ([report](report-final.json)):
0 missing events, 0 duplicate alert keys, one incident per address, and one monitor
incident. The monitoring alerts marked unverified in the 06 guide fired on synthetic
`collector_health` records and resolved on recovery records, except A10, which stays fired
by design for its 2-day window. Two failures are kept below:
the load generator's first trickle died on an expired token, and the verifier crashed on
Python 3.9 time strings. Both are fixed with tests. Releases remain **unsigned**.

## What ran

- Azure subscription `<subscription>` (identifiers in this folder are replaced by
  placeholders: `<subscription>`, `<app-object-id>`, `<service-principal-object-id>`;
  the cleanup verdicts were produced with the real values), `australiaeast`, run
  `bower-sentinel-20261103-054834`: resource group `rg-bower-sentinel-20261103-054834`
  (tagged `Project=bower-lab`, `RunId`), workspace `law-sentinel` (PerGB2018) with Microsoft
  Sentinel. Table, DCE and DCR came from `deploy/bicep/main.bicep`. A certificate-authenticated
  app registration `bower-sentinel-20261103-054834-ingest` held Monitoring Metrics Publisher
  on the DCR only, signed in through an isolated `AZURE_CONFIG_DIR`. No AWS resources and no
  collector were used. Every row was uploaded directly to the DCR stream (`method: direct`).
- Analytics content: `main.bicep` with `enableRules=true` and every other parameter at its
  default: 5-minute rules, `PT450M` look-back, `maxIngestionDelayMinutes=360`, hourly monitor
  ([deployment](deployment-analytics.json), [deployed rules](deployed-rules.json)). It was
  deployed at 05:52:24 UTC.
- Monitoring content: `deploy/sentinel/monitoring/monitoring.bicep` with `enabled=true`,
  `enableUnqualifiedTableNoIngestionQuery=true` and `noIngestionMinutes=10`. There was no
  DCR name, so no DCR or metric rules ([deployment](deployment-monitoring.json)).
- Diagnostics: Sentinel health (`SentinelHealth`) and workspace query audit (`LAQueryLogs`).
- Load: [`validation/load.py`](../../../deploy/sentinel/analytics/validation/load.py) uploaded
  600,000 synthetic firewall denials at 06:00 UTC, with event times spread over the
  previous two hours, on 8,192 IPv6 documentation addresses (slots 0–8,191, shared with the
  2,000-row probe; recorded bound 8 per address and bucket, below the threshold of 20).
  A 10-per-second on-time trickle followed on slots 8,192–16,383 (offset and count from
  its command line; it died before writing a summary, see below), then a second one on
  slots 16,384–24,575 ([load summary](load.json)). This put **about 640,000 rows** in every
  later run's look-back.
- Scenarios: [`validation/drive.py`](../../../deploy/sentinel/analytics/validation/drive.py)
  `direct` with collector id `sentinel-direct`, timed against the rules' 5-minute grid
  and the monitor's hourly grid.

## Results

| # | Goal | What was done | Result |
| --- | --- | --- | --- |
| 1 | Firewall rule alerts once per crossing; one incident per entity; copies raise nothing | f1, f2: 25 on-time denials each (198.51.100.10, .11); f3: 25 denials 45 min old (.12); f1b: a second crossing for .10 in the next bucket; b1: 12 logons (192.0.2.10). Exact copies of f1, f2, f3 and b1 22 min later (r1) and again 64 min later (r2); exact copies of f1b once, 53 min later (r2 only) | One `owned-window` alert per crossing in the run with `EndTime` 06:12:32 (f1, f2, f3, b1) and 06:22:32 (f1b). The copies (`extraRows` 50 each for f1, f2 and f3, 24 for b1 and 25 for f1b) raised **no** alert. .10's two keys joined **one** incident. 7 incidents in total, one per address, plus one monitor incident ([alerts](alerts.json), [report](report-final.json)). **Passed** |
| 2 | Catch-up | Firewall rule disabled 06:30:12; c1 (198.51.100.20) crossing first ingested 06:30:29; c2 (.21) at 06:36:04; re-enabled 06:55:57 (25.7 min) | On re-enable, Sentinel ran the window ending 06:51:06 at once: c1 was in slot 2 and alerted `catch-up-2`. c2 was in odd slot 1, waited, and alerted `catch-up-2` in the next run (06:56:06). No further alert for either key in 11 more runs, through the 07:46:06 window, which covers every retry slot up to 60 min after both crossings. Copies of c1 and c2 at 07:04 raised nothing. **Passed** |
| 3 | Monitor: at least two hourly runs; a late event once; an on-time event with a late replay in the same slot not reported | Slot 05:00: 4 events 400 min late and 2 events 3 days old (rewritten). Slot 06:00: 3 new events 400 min late, copies of the slot-05 events (including the rewritten ones), and 3 events first ingested 350 min after their time with copies 20 min later (370 min, same slot). Slot 07:00: 2 events 420 min late and copies of the slot-06 late events | Three scheduled runs (`EndTime` 06:47:32, 07:47:32, 08:47:32) raised `LateEvents` 6 (2 rewritten), 3 and 2: every late event once, no replay reported again, and the on-time/late-replay pair not reported. On the same slot the pre-fix query (the parent of `e12afe5`) reports 6 instead of 3 ([comparison](monitor-comparison.json)). The guide's 14-day hunting query gives 6, 3 and 2 for the same slots ([result](hunting-late-events.json)). **Passed** |
| 4 | `SentinelHealth` rule health | Diagnostic setting on `…/providers/Microsoft.SecurityInsights/settings/SentinelHealth`; a probe rule `Bower: health probe (deliberately failing)` whose function was deleted at 06:11:37 | Every scheduled run of the three rules whose window ended by 07:52 UTC has a row ([rows](sentinel-health.json), [queries](sentinel-health.kql)): firewall 20 succeeded and 1 failed, brute force 25 and 1, monitor 2 and 1. All 74 rows have `TimeGenerated` exactly 90 minutes after their window end, and collection ended at 09:22, so later runs (including the monitor's 08:47:32 run) were not collected. The firewall window ending 06:27:32 has no row because the rule was disabled before that run executed. The probe wrote 22 `Failure` rows (`ReferencedTableNotFound`) and was still enabled an hour after its first failure. **Each Bower rule's first run (window ending 05:47:32) failed** with `QueryGeneralError` ("failed after numerous attempts"): it ran before the first rows were queryable (05:57:56). This confirms the guide's prerequisite. The guide's query returned these rows, but its `Reason` column was always empty, so the query is fixed in the guide. **Passed (guide query corrected)** |
| 5 | Alert visibility | The guide's query over the 10 detection and monitor alerts | `TimeGenerated − EndTime`: 5 min 3 s to 5 min 11 s (p99 5 min 11 s). `ingestion_time() − EndTime`: p99 and max **8 min 7 s**. Budget: `alertVisibilityRuns × frequencyMinutes` = 10 min ([result](alert-visibility.json)). Within budget, but slower than the 7 min 20 s measured before. **Passed (1 min 53 s margin)** |
| 6 | Query cost at volume | About 640,000 rows in the look-back; one uncached query-API run per rule with statistics, plus `SentinelHealth` `QueryPerformanceIndicators` and `_LogOperation` | Firewall 2.4–2.5 s execution, 2.6–2.8 s CPU, 2.1 GB peak memory per node; brute force 0.6 s, 0.8–0.9 s CPU; monitor on the hour slot holding 634,172 ingested rows 2.5 s, 3.3 s CPU ([cost](query-cost.json)). Scheduled runs: maximum `TotalCpu` 2.83 s (firewall), 0.92 s (brute force), 2.66 s (monitor). Every scheduled run whose window ended between 06:00 and 07:52 UTC succeeded (later runs not collected), and `_LogOperation` was empty: no throttling, no ingestion or query warnings ([result](log-operation.json)). **Passed** |
| 7 | Monitoring smoke (06 guide items marked unverified) | Synthetic `collector_health` records per collector id ([records](health-records.json)) | A11 `syslog-tls-expiry` fired 34 s after a RELP+TLS listener reported a certificate 5 days from expiry and a revocation list due in 6 h, and resolved 5 min 51 s after a renewed record. The plain TCP listener in the same record did not fire. A10 `destination-credential` fired about 1.5 min after a `destination-credential` record; it stays fired for its 2-day window by design. A4 `queue-storage` (page use 82.5 %) fired about 4 min after ingestion and resolved 9 min 7 s after a 2.3 % record. A7 `source-transport-errors` fired for all three sources: TLS revocation and closed sessions, RELP retries in two records, and a Windows cursor conflict. All three resolved once the error records left the 30-minute window. A9 `table-no-ingestion` fired 10 min 57 s after the last ingestion (07:04:49; threshold 10 min) and resolved 16 min 12 s after ingestion resumed. A1 also fired, as expected, for each synthetic collector that stopped sending ([alerts](monitoring-alerts.json)). **Passed** |

The function was checked against the raw rows ([report](report-final.json) `parser`):
438 raw scenario rows formed 177 identities, the function returned 177 rows whose
`BowerCopies` sum to 438, and none of the 8 `collector_health` rows appeared.

**Sentinel behaviour measured:** in a scheduled run `now()` is the alert's `EndTime`, and
the run executes about five minutes later (alerts' `TimeGenerated` 5 min 3–11 s after
`EndTime`). Disabling a rule cancels any window whose execution time has not come yet.
Re-enabling it starts a new schedule whose first window ends about five minutes
**before** the re-enable. `SentinelHealth` rows had `TimeGenerated` exactly 90 minutes after their window end.
The diagnostic setting first had only the `Analytics` category; it was switched to
the `allLogs` category group (as Microsoft's guide says for analytics rules) at 06:36:44,
43 minutes in. Rows then appeared for every run up to the collection cut-off (windows
ending by 07:52), including runs before the switch.
Because rows lag by 90 minutes, the run does not show whether `Analytics` alone
would have been enough. Scheduled-rule queries did not appear in
`LAQueryLogs`. The incident `entities` API returned HTTP 500 for every incident (provider
"Microsoft XDR"), so the verifier now reads entities from the incidents' alerts.

## Failures and fixes (preserved)

1. **A first query that looked like a defect was not one.** Run with a substituted
   `now()` of 06:12:24, the firewall query returned f1 and f3 but not f2. The cause was
   the live run's own alert for f2, which had just become queryable in `SecurityAlert`
   and was correctly excluded as already alerted. A query with a substituted `now()` does
   not freeze `SecurityAlert`. The scheduled run had alerted all three.
2. **Load generator token expiry.** The first trickle died at 06:56 with HTTP 401 after
   33,900 rows. `load.py` reused an Azure CLI token for 20 minutes, and the CLI can hand
   back a cached token with only minutes left. Fixed during the run: refresh from `expires_on`
   with a 10-minute margin, and once on 401 (`test_load.py`). After review the margin is
   4 minutes, below the CLI's 5-minute cached-token refresh point. The second trickle ran 54.5 minutes
   without a retry. The gap from 07:04:49 to 07:55:37 with no ingestion is the one A9
   detected.
3. **Verifier crash on Python 3.9.** `verify.py` failed on `2026-11-03T06:11:40.84127Z`:
   Log Analytics trims trailing zeros, and Python 3.9's `fromisoformat` accepts only 3 or 6
   fractional digits. The verifier also compared `ingestion_time()` strings rather than
   times. Fixed, with `test_verify.py`.
4. **Incident entities API.** It failed with HTTP 500 for every incident. The verifier now
   falls back to `SecurityAlert.Entities` of the incident's alerts and records the source
   (`entitySource`) per incident (`test_verify.py`).
5. **Guide defect:** the 02 guide's rule-health query read `ExtendedProperties.Reason`,
   which does not exist. `Reason` is a column, and the issue code is in
   `ExtendedProperties.Issues`. Fixed in the guide and run live.
6. **Load guard gaps found in review (after the run).** The per-address check computed a
   trickle's bucket count from its rate, but a slow trickle sends at least one event per
   request (`--rate 0.01 --addresses 1` passed with a bound of 7 and sends 20 per bucket).
   It also accepted non-positive `--addresses`, defaulted the threshold and bucket instead
   of taking the deployed values, and could overrun its deadline or send one request
   larger than `--batch`. All fixed with tests. Recomputed with the corrected bound, the
   live loads stay well below the threshold: backfill 8 and trickles 2 events per address
   and bucket.

## Cost

`Usage` reports 601.95 MB of billable `BowerSecurity_CL` and under 0.3 MB of other
billable data ([usage](usage.json), [volume](table-volume.json): 940 bytes billed per load
row). Whether the Sentinel free trial or the Log Analytics free allowance applied to this
workspace was not verified. At pay-as-you-go list prices (approximately, not from the
price sheet) the run is about US$3 to US$4 of ingestion plus negligible alert-rule time.
The workspace was force-deleted, so no retention charges continue.

## Limits

- Direct uploads only: no collector, fault proxy, native WEF or syslog source. The
  collector replay paths were qualified on `4dabe15` content in
  [ws2b](../ws2b-20261102-003156/README.md) and are properties of the delivery path,
  which this content change does not touch.
- The load is about 640,000 rows: about 24 events per second over the 450-minute
  look-back, not several million. It was capped for cost; extrapolate with care. The
  firewall rule's 2.1 GB peak memory per node is the figure to watch at higher volume.
- One catch-up episode (two crossings), three monitor runs and a 3-hour run; no
  multi-day soak.
- The monitoring smoke used synthetic health records. It shows that the queries and alert
  rules fire and resolve on the documented fields; it does not prove that a collector
  emits those values in each fault.

## Cleanup

[cleanup.json](cleanup.json): strict audit, 9/9 absent. That covers the resource group,
tagged resources, the force-deleted workspace (exact `ResourceGroupNotFound`, no
soft-deleted copy), the application and service principal (empty listings, both purged
from deleted items with exact `Request_ResourceNotFound`) and role assignments. Key
material and the isolated CLI profile were deleted locally. No AWS resources were used.
