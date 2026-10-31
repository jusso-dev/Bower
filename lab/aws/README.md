# Disposable AWS validation lab

For the separate four-host native WEF/WEC and nftables → Sentinel pilot, see
[`PILOT.md`](PILOT.md) and its [10/sec, 100/sec burst, one-hour outage profile](pilot-envelope.json).
The relay/local-spool topology below does not establish Sentinel delivery.

Seven private EC2 hosts exercise three Linux and three Windows collectors against
an authenticated relay and local AMA spool. The seventh host serves the management
API and console. This is the first executable slice of [#136](https://github.com/jusso-dev/Bower/issues/136),
not the full stress/soak suite. It creates no Azure resources and cannot prove Sentinel delivery.

The first run's [scorecard](../../tests/scorecard/results/0.1.0-dev.250/aws-20261029-071208.md)
records successful eventual delivery and redaction checks, **failed latency and
recovery deadlines**, and the coverage still missing.

## Topology and access

- `Control`: Amazon Linux 2023, management on loopback port 4320. nginx exposes only
  enrolment and cryptographically authenticated collector requests on TLS 443.
- `Collector`: Amazon Linux 2023, loopback ingest 4318, mutual-TLS relay 4319,
  separate encrypted 4GiB queue disk, local AMA spool output.
- `Linux1`, `Linux2`: Amazon Linux 2023, loopback ingest 4319, mutual-TLS relay output.
- `Wec`, `Windows1`, `Windows2`: Windows Server 2022 Core, MSI service account
  `NT SERVICE\Bower`, Application/BowerLab event 9010 through a signed lab pack.
  **Wec is currently a host label, not a configured WEF/WEC server.**

All instances start as `t3.micro`; Windows supports a recorded `t3.small` fallback
when memory exceeds 90%. CPU credits use unlimited mode so empty credit balances do
not invalidate startup tests; surplus credits can cost extra. There are no public
instance addresses, SSH keys, inbound SSH/RDP or public admin routes. SSM is the
only administrative access. Development authentication is deliberately confined
to loopback; this does not test production Entra interactive sign-in.

Python 3.9+ and AWS CLI drive the lab. Windows uses the AWS-provided AWSPowerShell
module, already in the selected AMI. Record the resolved AMI IDs, artifact commit,
version and SHA-256s. No Python runtime dependencies are required.

## Plan and create

The default target is account `959038055523`, profile `homelab-admin`, region
`ap-southeast-2`. Use the configured credential process; never export credentials
or put keys in user data, scripts, SSM command arguments or this repository.

```bash
python3 -m unittest discover -s lab/aws/tests -v
python3 lab/aws/scripts/template.py /tmp/bower-lab.json
uvx cfn-lint==1.57.2 /tmp/bower-lab.json
python3 lab/aws/scripts/lab.py plan --state /tmp/bower-run/state.json --hours 8
# Review the generated template and CloudFormation change set before applying.
python3 lab/aws/scripts/lab.py apply --state /tmp/bower-run/state.json
python3 lab/aws/scripts/lab.py status --state /tmp/bower-run/state.json
```

`status` refreshes instance IDs/IPs, actual instance types, per-host CPU credit
modes and SSM status. It records `windowsFallback` and `cpuCredits` in the state
file used by the scorer. After a Windows resize, run it with
`--windows-fallback-reason "Measured memory exceeded 90%"` only if that reason
was actually observed; otherwise it records the resize with an unknown reason.
Continue only after the stack is complete and all seven hosts are Online.
`ssm.py` verifies account, exact host
ID, Project/RunId tags, running state and OS before sending any command.

## Stage and install

Prepare a dedicated **public artifact** directory containing these exact files:

| File | Contents |
| --- | --- |
| `collector.rpm` | Linux package downloaded from the selected green CI run |
| `collector.msi` | Windows package from the same run |
| `cli.tar.gz` | The run's Linux x64 CLI, `bower` at archive root |
| `management.tar.gz` | Self-contained managed Linux x64 `Bower.Management.Api` publish output and built console in `wwwroot` |

The first run used a managed publish with `PublishAot=false`,
`EnableRequestDelegateGenerator=true` and `EnableConfigurationBindingGenerator=true`.
Build the UI with `npm ci --ignore-scripts && npm run build` in
`ui/Bower.Management.Web`; copy `dist` into the published API's `wwwroot` before
archiving. The console gets its public auth configuration from the API.

```bash
python3 lab/aws/scripts/stage.py --state /tmp/bower-run/state.json \
  --artifacts /tmp/bower-public-artifacts --version VERSION \
  --source-commit SOURCE_SHA --artifact-commit ARTIFACT_SHA --artifact-run RUN_ID
python3 lab/aws/scripts/ssm.py Control lab/aws/scripts/control-bootstrap.sh --state /tmp/bower-run/state.json
# Wait for the command to succeed before installing nodes.
for host in Collector Linux1 Linux2; do
  python3 lab/aws/scripts/ssm.py "$host" lab/aws/scripts/node-bootstrap.sh --state /tmp/bower-run/state.json
done
for host in Wec Windows1 Windows2; do
  python3 lab/aws/scripts/ssm.py "$host" lab/aws/scripts/node-windows.ps1 --state /tmp/bower-run/state.json
done
```

The stage command uploads only its explicit allow-list and checksum manifest. It
adds the lab scripts and pack source. Control creates ephemeral TLS/signing keys,
signs and tests the pack, and stores per-host bundles in Secrets Manager. Private
keys and enrolment tokens never enter SSM output. Packages in the initial run were
unsigned, checksum verified, and reported as such. Do not mistake the lab signing
key for a production trust root.

Read command outcomes with `aws ssm get-command-invocation` using IDs recorded in
`commands.jsonl`; command submission alone is not success. Control setup is
one-time: do not remove its completion marker to overwrite a running executable.
`refresh-pack.sh` builds and tests exactly one new pack in an isolated directory,
then distributes it without resetting management or credentials. It supports pack
version changes and never selects an old build from the shared output directory.

## Run phases

Commit `tests/scorecard/aws-thresholds.json` **before** collecting scored results.
The scripts are individually repeatable with fresh phase IDs where supported;
this is currently an operator-sequenced campaign, not a single unattended runner.

1. Run `approve-and-check.sh` on Control, then `create-corpus.sh`. P0 requires all
   six collectors Active plus negative remote admin/assertion tests. The corpus
   contains four synthetic detector families and stays in the lab. The TFN value
   is the published detector test fixture, not a randomly generated identifier.
2. Run `load-smoke.sh` on all three Linux collectors; run `windows-events.ps1`
   once on each Windows host. The latter writes real Application events, not HTTP
   substitutes. Reusing a producer phase ID with new timestamps causes identity
   conflicts; use a fresh run or fresh supported phase name for a rerun.
3. Run `replay.sh` on Collector. Expected HTTP statuses: 202, 200, 409.
4. Run `load-steps.sh` concurrently on Linux1/Linux2. Aggregate requested rates
   are 1k then 5k EPS for 60 seconds each. Run `sample-linux.sh` concurrently to
   record memory, load, disk and queue states. The generator is bounded to 64
   in-flight requests per source; report its actual rate, including saturation.
5. Use `stage-receipts.py` to aggregate metadata-only receipts into an artifact
   readable by the central verifier. Run `verify-smoke.sh` on Collector with
   `ssm.py --phase baseline-drained` after preserving any initial timeout report.
6. Run `outage-relay.sh` on Collector and `outage-load.sh` on both Linux edges.
   The relay has an independent 45-second restart timer. After restart, run
   `verify-outage.sh`; it measures last output publication relative to service start.
7. Run `crash-load.sh` on each Linux collector. It kills the service during load,
   records transport failures, and measures service recovery separately from
   acknowledged-event recovery. Immediately stage receipts and run `final` on
   Collector **before disk-pressure or reboot tests**:

   ```bash
   python3 lab/aws/scripts/stage-receipts.py --state /tmp/bower-run/state.json
   python3 lab/aws/scripts/ssm.py Collector lab/aws/scripts/verify-smoke.sh \
     --state /tmp/bower-run/state.json --phase final
   ```

   Wait for that command to finish and preserve its result even if it fails. The
   verifier compares spool publication timestamps against each host's recorded
   crash time plus 120 seconds. Starting verification late cannot turn a late
   arrival into an on-time result. Missing crash timing metadata fails closed.
   Then run `disk-pressure.sh` only on Collector; it verifies the isolated mount,
   uses a bounded fill, and removes it in `finally` with an independent cleanup
   timer as a backstop.
8. Run `reboot.py Linux2 Wec Windows1 Windows2` with the state file. Collect
   `health-linux.sh`/`health-windows.ps1`, then `queue-integrity.sh` and
   `queue-integrity-windows.ps1` on the respective hosts. Windows delayed automatic
   startup must not be mistaken for instant recovery.
9. Stage receipts again and run `final-drained` for eventual delivery after the
   fault campaign. Keep the earlier `final` deadline result; never replace a
   failed deadline result with an eventual-success result.

```bash
python3 lab/aws/scripts/stage-receipts.py --state /tmp/bower-run/state.json
python3 lab/aws/scripts/ssm.py Collector lab/aws/scripts/verify-smoke.sh \
  --state /tmp/bower-run/state.json --phase final-drained
```

The verifier compares acknowledged event IDs and native Windows correlation IDs
against durable spool output. Derived privacy alerts intentionally share correlation
IDs and are counted as separate events, not duplicate source events. It scans
central persisted state, spool and service logs for raw corpus values, exporting
counts only. It does **not** scan source Event Logs, seed manifests, all edge logs,
or an Azure destination. Output latency uses spool file publication time.

For the console, use SSM port forwarding to Control's loopback 4320. Never expose
the development admin route. Record and terminate the session after checking Home,
Collectors and a detail view. This is UI smoke coverage, not an accessibility audit.

## Report and teardown

Download only metadata reports (not queue files, logs containing payloads or seed
manifests). `report.py` expects the phase layout above plus `ssm-metadata.json`
(whitelisted health/ledger command JSON), `dashboard-browser.json`, and optional
`cleanup.json`. Keep original diagnostics alongside the corrected reports.

```bash
python3 lab/aws/scripts/lab.py status --state /tmp/bower-run/state.json
# Save final observed sizes and credit modes before resources are deleted.
python3 lab/aws/scripts/cleanup.py --state /tmp/bower-run/state.json
# Review the exact inventory; --apply deletes only this stack and tagged lab secrets.
python3 lab/aws/scripts/cleanup.py --state /tmp/bower-run/state.json --apply
python3 lab/aws/scripts/report.py --input /tmp/bower-results \
  --state /tmp/bower-run/state.json --manifest /tmp/bower-public-artifacts/manifest.json \
  --thresholds tests/scorecard/aws-thresholds.json --output /tmp/bower-report
```

Always run cleanup, including after a failed test. It checks instances, the
captured disk IDs, endpoints, NAT gateway, Elastic IP and lab secrets after stack
deletion. The private report/artifact bucket expires objects after 90 days and is
retained. Secrets are created outside CloudFormation and explicitly deleted.
`lab.py destroy` alone deletes the stack but **not** those secrets; prefer
`cleanup.py`. A separate scheduled state machine is a backup for abandoned runs,
not a substitute for the final cleanup audit.

Costs include Windows licences, EBS, seven burstable instances, NAT gateway, five
interface endpoints, Secrets Manager, retained S3 and possible surplus CPU credits.
Rates vary; estimate from current Sydney-region prices and keep the bounded expiry.
The first run did not configure an AWS Budget alarm. Do not label this harness as
complete until the remaining #136 phases, cost alarm and production authentication
coverage are implemented and verified.

### WS1 syslog lab: record and audit EBS volumes

Use the same WS1 run state file throughout. After the stack is ready, run
`python3 lab/aws/scripts/syslog-lab.py status --state <state.json>` while all
four instances still expose their EBS mappings. It records each verified stack
instance's volume IDs in `volumeInventory`; keep the state file until cleanup is
verified. `destroy --state <state.json>` rechecks the account, stack, bucket and
instance ownership, refreshes the volume inventory and persists it before any
deletion. A previously recorded complete inventory can cover an instance already
terminated by the expiry guard; if no complete inventory exists, teardown stops
for investigation rather than claiming those volumes are absent.

After `destroy` completes, run `python3 lab/aws/scripts/syslog-lab.py audit --state
<state.json>`. The audit checks every recorded volume ID individually as well as
tagged volumes, and requires the specific AWS volume-not-found response for each
recorded ID. Missing or incomplete inventory, a surviving untagged volume, an
unexpected AWS error or an invalid subnet ID prevents a clean audit. Investigate
and remove any remaining resources only after verifying their ownership. A timeout
or a successful delete command alone is not proof that charges have stopped.
