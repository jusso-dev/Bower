# Final-candidate qualification — incomplete

Candidate `733eb7448a98e3ac449c8427753b799ad3fec5c1` · run `bower-ws6-20261101-011000`.
Snapshot: `2026-11-01T03:18:35.134051+00:00`. **General production readiness is not established.**

| Scenario | Requested | Native → accepted queue | Queried Sentinel | Result |
| --- | ---: | --- | --- | --- |
| Firewall steady, 10/sec | 600 | 600 → 600 | 600, no duplicates | EXACT PASS |
| Firewall burst, 100/sec | 6,000 | 6,000 → 6,000 | 6,000, no duplicates | EXACT PASS |
| Windows WEC steady, 10/sec | 600 | 600 → 600 WEC → 600 queue | 600, no duplicates | EXACT PASS |
| Earlier Windows steady attempt | 600 | 567 → 567 WEC → 567 queue | No qualifying claim | FAILED |
| Windows burst attempt, 100/sec | 6,000 | 3,179 → 3,179 WEC → 3,179 queue | No qualifying claim | FAILED |

The fresh Windows `final-steady-warm1` phase passed exact identity reconciliation:
600 native Security 4625 events, 600 WEC events, 600 accepted queue identities,
and 600 independently queried Sentinel identities/rows. Missing, extra and
duplicate counts were all zero. Native rate was
`9.998910/sec`.
Its 100-event connection warm-up has separate native/WEC/queue identity files
and never counts toward measured traffic. Each qualifying phase has its own
source and destination hashes in [summary.json](summary.json).

The earlier `final-steady` failure remains preserved: 600 authentication calls
returned code 1326 but produced only 567 observed native Security events. All
567 were forwarded and queued. Its native rate was
`9.455161/sec`, below the 9.9/sec qualification floor.
This does not establish 33 losses inside WEC/Bower. A structurally complete
export (`partialEvidence=false`) does not turn that failed phase into a pass.

The first warmed Windows burst also failed qualification: 6,000 authentication
calls produced 3,179 observed native events, all of which reached WEC and the
queue. Its native rate was 52.967652/sec. This is not proof of 2,821 losses in
WEC/Bower. Two subsequent worker-isolation diagnostics stopped before a complete
phase report; their bounded generator checkpoints, separate warm-up files and
explicit missing-phase lists are hash-verified and retained. They do not count
as passing phases. Testing is still active; later diagnostic/retry results are
outside this snapshot until independently verified.

The failed-burst Windows resource series captured 21/21 samples with zero sample
failures over 300.096991 seconds, peak pending 8 and zero dead letters. This does
not upgrade the failed traffic result.

The Linux final-burst sampler captured 21/21 samples with zero failures over
300.007176 seconds: unchanged boot, zero restarts/counter resets, peak pending
20, zero dead letters, peak sampled process RSS 70,639,616 bytes. The Windows
original sampler smoke failed all 5 metric samples under PowerShell 5.1 before
the disk-binding fix (zero available samples). That actual failed run is
preserved separately, with local file hashes in the machine-readable summary.
The fresh fixed sampler smoke then captured 5/5 samples with zero failures over
60.087869 seconds. A separate export attempt of that fixed run occurred before
60 seconds elapsed; it was premature and did not invalidate the subsequently
completed fixed series. Resource sampling is supporting
evidence and does not prove destination delivery.

One-hour outage/recovery, remaining idle tests, and independent AWS/Azure
cleanup verification remain pending. Do not infer cleanup from an expiry
schedule. Earlier `95d7c05` baseline attempts and the
[2026-10-31 monitoring drill](../ws6-20261031-074751/README.md) remain separate.

## Retained proof

- [Machine-readable evidence, query results and verified SHA-256 values](summary.json).
- [Rendered report](report.html) and [actual local-HTML screenshot](report.png).
- Failed WEC command: `1c1a2c32-85e7-40a5-95f6-ab6415b98d17`;
  export: `2ec3b389-a664-4c2a-b2a2-038db23672d3`.
- Passing WEC steady command: `884b4e95-bece-4fb9-8853-975437069a16`;
  export: `3174b762-94cf-4792-90ae-f1f16d1200a5`.
- Linux burst sampler export: `3337048d-039e-4531-84de-d865ee0765c7`.
- Windows completed sampler export: `1b985b39-7120-4eac-b3cd-28b134805d0f`;
  early attempt: `f9152c7c-ae7b-4aab-b145-1a60a136cc0d`.

All downloaded artifacts were verified against owned-host byte counts and
SHA-256 receipts. The screenshot depicts this real local HTML summary, not a
cloud portal. No raw payloads, credentials, private keys or token caches are
published. Protected source artifacts remain under the campaign's
`candidate-733eb74-r2/wec` and `resource-sampling` paths until approved cleanup.
