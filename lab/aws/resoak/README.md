# 72-hour re-soak harness (gap 7, check 7)

The re-soak of the scoped rollout (Windows WEF/WEC and firewall syslog over RELP with mutual TLS,
to the C# collector, to Microsoft Sentinel) on the final build. It extends the
[24-hour soak harness](../soak/README.md) and keeps its method
([07 guide, section 3](../../../docs/production-readiness/07-soak-and-release-validation.md#3-the-soak-method-all-environments)).
What changed after the first soak, and why:

| Change | Why |
|---|---|
| 72 hours, `m6i.large` for all four hosts (no CPU credits), recorded in the template | The first soak measured the t3 CPU-credit policy on the WEC, not Bower |
| The exact CI candidate: run, build number, commit, version from the package names, SHA-256 of the RPM and MSI, the CLI's `--version` (`resoak.py candidate`) | A soak counts only for the build it records ([release versioning](../../../docs/operations/release-versioning.md)) |
| [`preregistration.json`](preregistration.json): the six criteria copied verbatim from the 07 guide (a test keeps them identical), the fault schedule and the fault accounting, committed before the run | Pass criteria are fixed before any data exists |
| Scheduled faults run by host agents (`fault-agent.sh`, `fault-agent.ps1`) | Faults happen on the hosts with no operator session, also across reboots |
| Per-minute canaries at both sources | Continuous end-to-end proof, independent of the bulk generators |
| A RunId-owned identity bucket `<RunId>-ids`, outside the stack (`resoak.py bucket`) | The first soak's identity lists were deleted with the lab, so its accepted-extras check could not be re-run |
| Firewall identities past 2,000,000 (`syslog-host.py nft_ports`) | 72 hours need 2,689,200 identities; the old mapping held 2,000,000 |
| A separate WEC union task (30 minutes, 25-minute limit) | A union of millions of ids must not skip the 5-minute samples |
| Credential lifetime 7 days (`azure-environment.py --credential-days`), results kept 7 days | The 2-day lab certificates and 1-day result expiry would end a 72-hour run early |

Releases and packages are **unsigned** (signing is deferred). Bower still refuses unsigned or
untrusted packs; the packs here are signed with a run key.

## The schedule (pre-registered)

The soak starts at hh:05 UTC. Load: 10 events/s per collector plus 60 s at 100/s every 4 hours
from +2 h: 2,689,200 events per collector. Faults at +h:20 (wall clock hh:25, clear of the hourly
retention at hh:00 and of every burst):

| Fault | At | Hosts | Restarts | Expected outcome (abridged) |
|---|---|---|---|---|
| F01 destination outage, 30 min | +1:20 | Linux, Wec | none | Queue durably, resume within 5 min of restore, drain, 0 missing; `collector-health-missing` or `queue-backlog` fires and resolves |
| F02 sender restart | +4:20 | Sender (rsyslog), Dc (WinRM, the WEF forwarder) | none | RELP and WEF resume; 0 missing |
| F03 log rollover | +8:20 | Sender, Linux (`journalctl --rotate`) | none | `imjournal` reads across; 0 missing |
| F04 syslog TLS certificate rotation | +12:20 | Linux | none (hot reload) | New certificate loaded, no restart, 0 missing |
| F05 collector kill | +26:20 | Linux (`SIGKILL`, systemd restarts) | firewall | One new process within 60 s; 0 missing |
| F06 collector kill | +28:20 | Wec (`Stop-Process -Force`, SCM restarts) | WEC | One new process within 60 s; 0 missing |
| F07 host reboot | +31:20 | Wec | WEC (and boot) | Back within 15 min; DC buffers; 0 missing |
| F08 host reboot | +33:20 | Linux | firewall (and boot) | Back within 10 min; sender resends; 0 missing |
| F09 ingestion certificate rotation with overlap | +35:20 | Linux, Wec | both | New certificate, restart, no `destination-credential`; 0 missing |
| F10 sender restart | +45:20 | Sender, Dc | none | As F02 |
| F11 log rollover | +57:20 | Sender, Linux | none | As F03 |
| ForwardedEvents full (natural) | about +50 to +56 h | Wec | none | The 4 GiB channel starts overwriting; reader `gaps`, `resets`, `cursorConflicts` stay 0 |
| Sentinel throttling | **skipped** | — | — | Not simulated: a real 429 needs a TLS-intercepting proxy the collector trusts or overloading the shared endpoint. Recorded as skipped, not passed |

The accounting rules (in full in `preregistration.json`): criterion 1 and 6 apply to the whole run
unchanged. Criterion 2 allows exactly the scheduled restarts and reboots, each inside its fault
window. Criterion 3 is evaluated on hours 3–24 (no restart in it) and on +38:20 to +72:00 (3 hours
after the last scheduled restart); both must pass. Criterion 4's p99 is over events outside every
fault window. Criterion 5 excuses only an alert of a rule the fault lists, starting inside that
fault's alert window; `syslog-tls-expiry` and `destination-credential` are never excused. The run
passes only if all six criteria hold for both collectors, every fault outcome holds and the
reported version is the candidate's.

## Run it

Everything below uses public identifiers only. Credentials are created in the private lab
directory and fetched by the hosts through their instance roles.

```bash
export BOWER_LAB_RUN_ID=bower-resoak-$(date -u +%Y%m%d-%H%M%S) BOWER_LAB_PROFILE=resoak \
  BOWER_LAB_CIDR=172.31.248.0/24 BOWER_LAB_DIR=/tmp/$BOWER_LAB_RUN_ID
mkdir -m 700 "$BOWER_LAB_DIR"
# Dry run only: a guard of at most 12 hours (the 72-hour run uses the profile's 80 hours).
# export BOWER_LAB_EXPIRY_HOURS=12
R=lab/aws/resoak/resoak.py
python3 $R candidate --ci-run <CI run id of the candidate>   # version, build, commit, SHA-256
python3 $R bucket create                                     # <RunId>-ids, tagged, 30-day guard
python3 lab/aws/upgrade-recovery/lab.py plan                 # review template.json, then
aws --profile homelab-admin sts get-caller-identity          # 959038055523
python3 lab/aws/upgrade-recovery/lab.py create
python3 $R azure                                             # workspace, DCE/DCR/table, Sentinel, alert rules, 2nd ingest cert
python3 lab/aws/upgrade-recovery/lab.py status               # CREATE_COMPLETE and SSM Online
python3 $R stage [--plan dryrun]                             # CA, certificates, signed packs, manifests, plan -> run bucket
python3 $R deploy                                            # DC forest, WEC join and subscription, collectors, sender (rsyslog 8.2610.0)
python3 $R smoke [--plan dryrun]                             # soak agents, then the 15-minute smoke generators
```

After the smoke (start + 16 minutes), export and reconcile it. A smoke that does not reconcile
stops the run:

```bash
python3 $R smoke-export                # DC native window, a DC agent tick, fresh accepted unions
python3 lab/aws/resoak/reconcile.py fetch --lab-dir "$BOWER_LAB_DIR"
python3 lab/aws/resoak/reconcile.py smoke --lab-dir "$BOWER_LAB_DIR" --out "$BOWER_LAB_DIR/smoke.json"
python3 $R start [--plan dryrun]       # fault agents, canaries, then the soak generators; prints the end time
```

`resoak.py status` prints every host agent's last record. At +1 h 30 min run the interim
reconciliation (`reconcile.py fetch`, then `interim`). After the end plus 30 minutes the agents
publish their final exports by themselves; then `fetch` and `final`. Export the window after the
end on demand if the DC generator drifted into it (`dc-native-window.ps1 NAME=h72 FROM=<end>
TO=<end+3600>`).

## Clean up

1. `aws sts get-caller-identity` is `959038055523`; the stack, the run bucket and the identity
   bucket carry `Project=bower-lab` and `RunId=<RunId>`.
2. Empty the run bucket, `aws cloudformation delete-stack --stack-name <RunId>`, wait for
   `stack-delete-complete`.
3. `python3 lab/aws/monitoring/azure-environment.py cleanup --state-dir $BOWER_LAB_DIR/azure --apply --timeout-seconds 1200`.
4. Only after the final reconciliation is accepted: `python3 $R bucket delete --reconciled <final.json>`.
5. `relp-cleanup-audit.py` with the stack resources plus the identity bucket, then remove
   `$BOWER_LAB_DIR`.

## Files

| File | Runs on | Does |
|---|---|---|
| `preregistration.json` | — | Criteria (verbatim), profile, canaries, faults with expected outcomes, accounting, skipped faults |
| `resoak.py` | operator | `candidate`, `bucket`, `azure`, `stage`, `deploy`, `smoke`, `start`, `status` |
| `fault-agent.sh` | Linux, Sender | Per-minute timer: due faults (outage with an independent restore timer, kill, reboot, rollover, TLS and ingestion rotation, rsyslog restart), the sender's canary rule and canaries |
| `fault-agent.ps1` | Wec, Dc | Per-minute and at-start-up task: outage (firewall rule with an independent restore task), kill, reboot, ingestion rotation, WinRM restart, the DC's canary binds |
| `reconcile.py` | operator | `fetch`, `smoke`, `interim`, `final`: the soak reconciler plus canaries, fault windows, the registered accounting and the verdict |
| `probe.sh`, `probe.ps1` | all | Readiness probe after a reboot (boot identity only) |
| `dc-tick.ps1` | Dc | One immediate tick of the DC soak agent (uploads generator records) |
