# wecfix lab (Windows reader throughput and retention collisions)

The harness behind [the wecfix evidence](../../../docs/evidence/wecfix-20261103-043750/README.md).
Follow [`../AGENTS.md`](../AGENTS.md): synthetic data only, `Project=bower-lab` and `RunId`
on everything, account and ownership checks before every command and teardown, SSM only.

It reuses the soak tooling from PR #170 (`lab/aws/upgrade-recovery/lab.py`,
`monitoring/azure-environment.py`, `upgrade-recovery/probe`, `soak/*`) with a `wecfix`
stack profile: `Dc`, `Wec` and `Wec2`, all `m6i.large` (no CPU credits), 60 GB gp3, an
11-hour expiry. That profile is a small patch to #170's `lab.py`, recorded in
[`operations/lab-profile-wecfix.diff`](../../../docs/evidence/wecfix-20261103-043750/operations/lab-profile-wecfix.diff);
fold it in once #170 merges. `lab.py run HOST SCRIPT KEY=VALUE` renders the `{{...}}`
placeholders below.

| Script | Runs on | Does |
|---|---|---|
| `dc-forwarder.ps1` | Dc | Source-initiated forwarding of Security 4625 to both WECs, so they read identical channels |
| `wec-subscription.ps1`, `wec-batching.ps1` | Wec, Wec2 | The soak subscription (100 events, 1 s); larger batches only while pre-filling |
| `dc-fill.ps1` | Dc | Pre-fill: real 4625s from local network logons of the unknown user `bower-fill` (about 1,900/s) |
| `generator-windows.ps1`, `dc-generator.ps1` | Dc | The soak's measured load (`bower-probe` NTLM LDAP binds): 10/s, 100/s for 60 s at +2 h |
| `dc-burst.ps1` | Dc | Extra load at a fixed rate (the generator's own LDAP type) to reach soak-level queue rows, or a sustained burst |
| `wec-install.ps1`, `wec-upgrade.ps1`, `wec-retention.ps1` | Wec, Wec2 | MSI install (old or new build), in-place upgrade under load, retention hours |
| `wec-agent.ps1` | Wec, Wec2 | Per-minute samples (collector user/kernel CPU, Event Log service CPU, `/v1/status`, `ForwardedEvents`), accepted-identity union, uploads |
| `wec-bench.ps1` + `bench/` | Wec, Wec2, Dc | Reader and queue micro-benchmarks (`info`, `profile`, `continue`, `source`, `queue`, `rows`) |
| `wec-profile.ps1` + `etlstacks/` | Wec, Wec2 | In-box WPR CPU sampling of the collector, reported per module and frame with the build's PDBs |
| `wec-logs.ps1` | Wec, Wec2 | Counts of the collector's own log events (1002, 1009, 1201 with purge size) |
| `dc-native.ps1` | Dc | Native 4625 identities per window (`Bower.LabProbe native`) |
| `reconcile.py` | operator | Native = accepted = Sentinel per WEC using source generation time, latency quantiles, CPU per hour |

`bench/` and `etlstacks/` are lab-only tools (not shipped); `etlstacks` uses
`Microsoft.Diagnostics.Tracing.TraceEvent` to read the WPR trace and resolve symbols.
Every output is counts, positions and timings; traces are deleted after reporting.

Numeric reader lag in newly captured samples is the observed difference between receiving
channel record IDs, not a count of unread events or proof of channel continuity. It assumes
no unobserved clear or reset; a clear followed by sufficient regrowth between samples can
evade the recorded counters. Older samples without the native-bookmark basis are unknown.
The Windows PowerShell 5.1 sampler uses the installed, hash-verified .NET 10 lab probe's
`receiving-position ForwardedEvents` command rather than accessing a private Framework
bookmark property. The probe uses Bower's bounded native bookmark parser and does not
export event content. If the command fails or returns no usable position while the channel
has records, `newestRecordIdState` is `missing-bookmark-with-records`; treat lag as unknown
and correct the probe before qualification. The new probe and sampler still need live WEC
validation; the Windows CI check uses a real local Application or System log, not WEF.
Reconciliation only uses a position when its native-bookmark basis is present and the
position self-check says `observed`; missing or inconsistent states remain unknown.
The probe emits a fixed, compact three-field JSON response; the sampler accepts only that
exact field order and a bounded positive integer. Duplicate, escaped or extra properties,
alternative whitespace and noncanonical numbers fail closed rather than being interpreted
by PowerShell's permissive JSON parser. A differently formatted or older probe therefore
reports the position as unknown until the matching verified probe is installed.

The shared lab probe's `queue-union` exports only the normalized WEC source generation
time in a fourth TSV field, never a queue payload. Legacy rows without that field are
indeterminate unless the original retained queue row can safely supply it. Reconciliation
reports `availableObservedSetsEqual` separately from exact qualification, together with
available sampling, union and error-log observations. `exact` remains false because the
current harness cannot independently verify native channel continuity or complete union
capture; a matching set of available observations does not prove either. Missing or invalid
artifacts and observed union failures are reported, not treated as successful capture.
The reported p99 and `observedSampleP99WithinLimit` describe only arrived samples; the
full-workload `latencyPassesPilotLimit` remains indeterminate while workload, capture and
destination completeness are unproven. Negative destination latencies indicate clock skew
and also make the observed-sample comparison indeterminate. Specify one existing
`--lab-dir` and one `--out` path outside the lab input tree. The tool rejects output
aliases to input files, including symlink and hardlink aliases, before touching the report.
It fails closed if it cannot inspect the tree or finds a directory symlink that prevents a
complete alias check. Avoid modifying the input tree concurrently with reconciliation.

Once the paths are safely identified, the tool attempts to invalidate an old report
before validating other arguments and publishes the final report atomically. Once that
invalidation succeeds, an argument, input or destination failure leaves an invalid
placeholder. Ambiguous or unsafe paths, a filesystem failure, or a help invocation cannot
guarantee invalidation. Always require exit status zero and `status: complete` before
consuming an output file. A help invocation does not run reconciliation; do not consume
its output as a fresh result.

To exercise the probe against a disposable local SQLite database, build it and run:

```sh
dotnet build lab/aws/upgrade-recovery/probe/Bower.LabProbe.csproj -c Release
BOWER_WECFIX_PROBE_DLL="$PWD/lab/aws/upgrade-recovery/probe/bin/Release/net10.0/Bower.LabProbe.dll" \
  python3 -m unittest discover -s lab/aws/tests -p 'test_wecfix_probe.py'
```

Set `BOWER_WECFIX_DOTNET` to the dotnet executable if it is not on `PATH`. The probe
integration tests are skipped unless `BOWER_WECFIX_PROBE_DLL` is set.
