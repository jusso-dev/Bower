# Isolated security qualification — 1 November 2026

This report records an isolated rerun using the frozen C# collector at commit
`733eb7448a98e3ac449c8427753b799ad3fec5c1` and synthetic data. It is evidence
for the scenarios below, not a general production approval. The Linux executable
SHA-256 was `785c1b06d642d9fec4998d1693148caa482bcebb395e77293fc08902d00fc41e`;
additional binary, test-source and profile hashes are in [summary.json](summary.json).
The test host was a separate, private AWS Linux instance. Its syslog sender and
collector communicated over loopback; their certificates, paths, peer name and
source topology differed from the final multi-host sender.

## TLS and source retention

The first run used the earlier WS5 rsyslog 8.2204 profile: persistent TLS, octet
framing and a 100,000-message linked-list, disk-assisted queue. It did not
explicitly enable resend-on-reconnect or TCP keepalive. Baseline, server
certificate rotation and client CA overlap each accepted all 100 sent frames.
A mismatched-key reload was counted, and the prior certificate continued to
serve accepted handshakes. Six invalid-client categories were refused. When the
server presented a certificate for the wrong name, zero frames were accepted
during that interval; after the correct certificate was restored, the complete
phase accounted for all 30. The
original report does not record a separate repair timestamp or post-repair count.

The targeted second run checked the final recommended delivery settings,
including resend-on-reconnect, keepalive 60/10/6, a 200,000-message queue,
2 GiB disk cap, watermarks and checkpoint settings. It used the same isolated
loopback topology, not a vendor firewall or the main multi-host sender.

| Targeted phase | Sent | Accepted into the local durable queue | Missing before acceptance |
| --- | ---: | ---: | ---: |
| Before client revocation | 30 | 30 | 0 |
| While client was revoked | 40 | 0 | 40 |
| After certificate reissue | 30 | 30 | 0 |
| Before collector restart | 30 | 30 | 0 |
| After collector restart | 70 | 69 | 1 |

The collector closed the revoked session and refused the revoked handshake and
reconnect. That is the intended fail-closed security behavior. The 40 missing
frames show that this sender did not retain all events before collector
acceptance during revocation; the restart lost one more. Zero duplicate events
were observed by the local source counter in each targeted phase. The earlier
WS5 profile also observed 40 missing during revocation and one on restart.
These counts are local source/queue observations, not Sentinel delivery proof.
The report preserves source-set hashes and per-interval counts; its phase end
timestamps precede the bounded queue-settling wait and do not measure drain time.

The [main final-candidate firewall campaign](../ws6-20261101-final/README.md)
separately recorded a 6,000-event `a-restart` source-to-queue-to-Sentinel pass
on its multi-host configuration. Both observations matter: neither proves that
all appliances or all pre-acceptance failure modes are lossless. The first
production rollout needs a named sender, a measured retention/replay profile and
an explicit treatment of events rejected before durable acceptance.

## Privacy and destination credentials

The isolated host executed 18 syslog adversarial cases. The source report records
individual outcomes and counter deltas in [summary.json](summary.json); completion
of all cases is not a blanket pass for every input. Scans found zero matches for
the synthetic privacy markers in the queue database, WAL, SHM, collector journal
and status output. Marker values and raw payloads are not included here. This is
a local pre-persistence/operational-file check, not a Sentinel privacy sweep.

Two separate five-event cases exercised a dedicated DCR-scoped test identity.
All ten events received HTTP 202 at the collector. A rejected synthetic secret
was classified `destination-azure-credential-failed` for all five queued events;
a process-local blocked HTTPS proxy was classified `destination-azure-unavailable`
for the other five. After each isolated collector restarted with the valid test
certificate and normal network, all five queue rows reached delivered state.
An independently authorized verifier then queried Sentinel: 10 expected IDs,
10 accepted IDs and 10 destination rows matched, with zero missing, extra or
duplicate IDs. The [expected](credential-expected.ids),
[accepted](credential-accepted.ids) and [destination rows](credential-sentinel-rows.json)
contain bounded synthetic identities; the [query](credential-sentinel-query.kql),
query time, role and hashes are in the [proof](summary.json). These tests do not
qualify managed or workload identity, a real production credential rotation or
all credential failure modes.

## Monitoring and cleanup

The maintained Linux host check used a separate 32 MiB tmpfs and read-only live
collector status. At 6 MiB free it reported `disk-free` WARNING; at 2 MiB it
reported CRITICAL. After removal of the test filler, all 32 MiB was free and
there was no `disk-free` finding. The overall check still reported WARNING on
recovery, so this result closes only the filesystem finding. The owned mount
was unmounted and removed. No real collector queue volume or settings were
modified; this was not a full-queue or disk-exhaustion test of the collector.

A separate direct-ingestion synthetic health record reported 95% queue page
usage. The actual Azure `queue-storage` alert entered Fired at 03:54:00 UTC and
Resolved at 04:10:00 UTC after a newer healthy fixture. The alert had no action
groups. HTTP 204 for each fixture meant only accepted for processing; the queried
record and actual alert transitions provide the evidence. This does not prove a
real host generated the signal or that the alert fires when its queue is already
full. The synthetic collector can later generate a synthetic health-missing
alert; the disposable workspace is removed with the main campaign.

The dedicated security test's Azure application, service principal and DCR
role assignment were removed. Its separate AWS stack reached DELETE_COMPLETE;
the exact instance was terminated and its volume, subnet, security group, route
table, bucket, roles, instance profile and expiry schedule were verified absent.
The shared VPC and NAT remained available. Host test key paths were removed before
termination. See [cleanup-proof.json](cleanup-proof.json). This proves cleanup
only for the separate security rerun; it does not prove cleanup of the ongoing
main campaign.

The private original reports, including synthetic marker strings, were not
copied here. The summary retains their hashes and sanitized case outcomes.
