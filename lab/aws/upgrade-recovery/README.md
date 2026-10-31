# Upgrade, crash and restore lab (populated queues)

The harness behind [the ws4 evidence](../../../docs/evidence/ws4-20261031-074918/README.md)
and the [upgrade and recovery guide](../../../docs/production-readiness/04-upgrade-backup-recovery.md).
It is an operator-sequenced campaign, not an unattended runner. Follow
[`../AGENTS.md`](../AGENTS.md): synthetic data only, an owned `Project=bower-lab` /
`RunId` tag on everything, account and ownership checks before every command and
teardown, no public addresses, and SSM only.

## Topology

`lab.py plan|create|status|run|wait|power` builds a stack in a dedicated private subnet,
with an EventBridge Scheduler termination guard:

- `Dc`: domain controller and WEF source;
- `Wec` and `Wec2`: real WEC `ForwardedEvents`; `Wec2` is the fresh restore target;
- `Linux`: RPM collector, then Docker;
- `Linux2`: mutual-TLS sender, then the fresh restore target.

Set `BOWER_LAB_RUN_ID` (`bower-ws4-UTCyyyymmdd-HHMMSS`) and `BOWER_LAB_DIR` (a private
`0700` directory outside the checkout). `lab.py run HOST scripts/X KEY=VALUE` renders the
`{{...}}` placeholders and sends the script with SSM to the ownership-checked instance.
It writes `commands.jsonl` and the results into `BOWER_LAB_DIR`. Placeholder values are
public identifiers only. Hosts fetch credentials from the owned bucket themselves, and
never print them.

## Traffic and identity reconstruction

- `scripts/generator.ps1` runs real NTLM LDAP bind failures against the DC at a fixed
  rate. The DC's own Security log is the source of truth.
- `sender.py` writes RFC 5424 frames over mutual TLS. Frame *n* is a pure function of the
  stream, base time, rate and *n*, and the sender resends a bounded window after
  reconnecting. `expected.py` recomputes the collector's syslog event id
  (`SyslogRecord.EventId`) for any sequence number. Use one stream name per logical stream:
  a different `--stream` changes the frames and therefore the ids.
- `probe/` (`Bower.LabProbe`) is a read-only queue snapshot (counts, cursors, ledger head,
  quick check). It also exports native 4625 identities through the signed parser and
  default identity redaction, and applies the same redaction to expected ids (`redact`).
  It writes event ids only to `*.ids` files in the private directory. Commit counts and
  digests only.

## Sequence used

The `scripts/*-snap.*` scripts run before and after each step and record service identity,
package version, executable, configuration, pack and public-key hashes, ACL and permission digests,
whether secrets are unchanged (a boolean against an on-host baseline), queue states, cursors
and `/v1/status`.

1. Install the baseline packages, configure them (`linux-setup.sh`, `wec-install.ps1`) and
   start the traffic.
2. Run connected, then start the outage (`*-block.*`), so the queue holds delivered, leased
   and pending rows.
3. Upgrade in place under load: `linux-upgrade.sh`, `wec-msi.ps1`, `docker-run.sh`.
4. Crash under load: `linux-kill.sh` / `wec-kill.ps1`. Force a stop/start:
   `lab.py power HOST stop-force|start`.
5. Online backup (`*-backup.*`), restore on the fresh hosts (`linux2-restore.sh`,
   `wec2-restore.ps1`), lose the original host, re-point the sources.
6. Downgrade (`linux-upgrade.sh VERB=downgrade`, `wec-msi.ps1 MSI=old.msi`), future schema
   (`schema-future.sh`), v1 → v2 bookmarks on the DC (`dc-v1test.ps1`).
7. Stop the traffic, drain, take the final snapshots and native exports, query the
   destination with a separate verifier identity, and reconcile ids.
8. Tear down, then run `verify_cleanup.py` for an independent audit of every AWS and
   Azure resource with the run id.

Failures seen with this harness are recorded in the evidence: an nftables reserved word,
Windows PowerShell 5.1 treating CLI stderr as an error, and service-user path access. Keep
new failures; never replace a failed result with a later pass.
