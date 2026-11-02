# Replay-safe detections, second live run — 2 November 2026

**Strict result: passed.** Every scenario delivered all its distinct events. The function
collapsed every replay path to one row per `(CollectorId, EventId)`. Each expected entity
had exactly one alert and one incident. No detection key alerted twice, and no late event
was missed. This run qualifies the content committed at `4dabe15`
([hashes](artifact-manifest.json), [deployed rule settings](deployed-rules.json)). The
[first run](../ws2-20261031-075516/README.md) failed, and its retained evidence explains the
fix. Release packages remain **unsigned**.

## What ran

- Azure subscription `945092a0-2500-4b25-85a4-99f1c3135906`, `australiaeast`, run
  `bower-ws2b-20261102-003156`: resource group `rg-bower-ws2b-20261102-003156`, workspace
  `law-ws2b` with Microsoft Sentinel. The table, DCE and DCR came from `deploy/bicep/main.bicep`.
  A certificate-authenticated app registration held Monitoring Metrics Publisher on the DCR
  only. No AWS resources were used.
- The analytics content was deployed from `deploy/sentinel/analytics/main.bicep`
  ([deployment](deployment.json)) with `enableRules=true`, `frequencyMinutes=5` and
  `maxIngestionDelayMinutes=120` (look-back `PT205M`).
- The collector was a local Release build of the branch, run with
  `BOWER_COLLECTOR_ID=ws2b-collector-01`, lease 90 s, deadline 60 s and `collector_health`
  every 60 s. It delivered through the loopback fault proxy. Events entered `/v1/events` as
  pack-shaped Windows 4625 and firewall-deny envelopes; scenarios e, f and k uploaded
  directly to the DCR stream (`method: direct`). The archive replay ran through two
  additional local collectors ([fault and replay log](fault-injection.json)).
- All scenarios were started within 15 minutes of each other, so the outage, the late
  originals and the late replays overlapped one schedule of 5-minute rule runs.

## Results

The [verifier report](report-final.json) contains exact counts from Log Analytics and
alerts from `SecurityAlert`. Incidents and their entities came from the Sentinel API.

| Scenario | Method | Distinct / rows | Result |
| --- | --- | --- | --- |
| a clean | collector | 37 / 74 | 1 alert and 1 incident per address. The 37 extra rows are archive replay m. |
| b1 response dropped, network back | collector, fault proxy | 37 / 49 | 12 replayed; no extra alert |
| b2 collector killed (SIGKILL) after Azure accepted the upload | collector | 37 / 49 | 12 replayed 94.7 s later after lease expiry; no extra alert |
| c response dropped at outage start | collector, fault proxy | 37 / 111 | replayed 4,099 s later, and again by restore j; no extra alert |
| d1, d2, d3 originals during a 4,029.8 s outage | collector | 111 | first ingested up to 4,039 s after their event time; each address alerted once, in the first owned window after restoration (01:54:57 and 01:55:52 runs). d2 crossed its threshold only with its late half. |
| e beyond tolerance (150 min), rewritten time (3 days) | direct | 15 / 15 | no detection alert; 1 monitor incident (host `ws2b-direct`) |
| f originals, f2 identical copies 75 min later | direct | 37 / 74 | 1 alert per address; the copies raised none |
| j restored queue backup (133 pending rows) | collector, `sqlite3 .backup` | 133 / 303 | all 133 redelivered after the restore; no extra alert |
| k crossing while the firewall rule was disabled (22.4 min) | direct | 25 / 25 | exactly one alert, `catch-up-2`, in the first run after re-enabling; later runs found it in `SecurityAlert` |
| l dead-letter replay (`bower queue replay`) | collector, dead-letter state simulated in SQLite after acceptance | 12 / 24 | 1 alert, no extra |
| m archive replay of a, replay collector with the same id | `bower archive replay` | 37 replayed (HTTP 202) | collapsed with the originals; no extra alert |
| m′ the same replay into a collector with another id | `bower archive replay` | 0 stored | refused (`collector-mismatch`, CLI exit 2) |

The function was checked against the raw rows with exact counts. 631 raw rows formed 351
identities, the function returned 351 rows whose `BowerCopies` sum to 631, and
`(CollectorId, EventId)` and `EventId` gave the same 351. 176 `collector_health` rows were
in the table and none appeared in the function. The scheduled-run timing again showed
`now()` equal to the alert `EndTime`.

**Simulated parts:** the fault proxy simulated the ambiguous acknowledgement and the outage,
which a firewall rule produced in the native pilot. Dead-letter state in scenario l was
written directly to SQLite. Events came through the collector's HTTP intake or the
Logs Ingestion API, not native WEF or syslog sources; native sources were qualified in the
[native pilot](../pilot-native-20261030/README.md).

## Not run

- RELP resends were not driven here. The RELP campaign
  ([`fw-20261101-111911`](../fw-20261101-111911/README.md)) produced Sentinel duplicates after
  kill/restart that collapse by `EventId` within one collector, which is the same key.
- No multi-day soak and no load test of the queries at production volume.

## Cleanup

See [cleanup.json](cleanup.json): strict audit, exact not-found codes only.
