# AWS lab and stress testing

The [disposable AWS harness](https://github.com/jusso-dev/Bower/tree/main/lab/aws)
tests three Linux and three Windows collectors, a mutual-TLS relay and the
management console on real EC2 hosts. All data is synthetic. Administration uses
SSM; instances have no public addresses or inbound SSH/RDP.

This first campaign ends at a local AMA spool. **It does not prove arrival in
Microsoft Sentinel.** Sentinel verification was explicitly deferred and no Azure
resources were created. A real destination query is still required for
[delivery evidence](evidence-bundles.md).

## First measured run

Run `20261029-071208` used package `0.1.0-dev.250`. Linux collectors ran on
`t3.micro`; Windows started there and moved to `t3.small` after bootstrap memory
exceeded 90%. The results are committed in the
[scorecard](https://github.com/jusso-dev/Bower/blob/main/tests/scorecard/results/0.1.0-dev.250/aws-20261029-071208.md).

| Check | Observed outcome |
| --- | --- |
| Event accounting | All 45,220 expected source events eventually arrived; zero acknowledged loss, duplicate output IDs or denied events in output |
| Privacy | Zero raw seed hits in the central spool, persisted state and service journal for the four tested detector families |
| Queue integrity | All six collector ledgers intact after the tested faults |
| Relay interruption | 1,000 buffered source events drained within 23.2 seconds after restart |
| Process crashes | Linux service health recovered in about 6 seconds; two central events waited for a five-minute lease to expire |
| Full isolated queue disk | 99 requests received 503 back-pressure and one was accepted; fill removed afterward |
| Windows reboot | Automatic service startup took about 131 seconds due to delayed startup |
| Load | Requested 1k/5k EPS steps achieved about 341/319 EPS combined; local output p95 was about 250 seconds |

The overall score is **failed**: the precommitted 60-second latency and 120-second
recovery deadlines were exceeded. Eventual delivery does not erase those failures.
See [throughput investigation #153](https://github.com/jusso-dev/Bower/issues/153)
and [recovery investigation #154](https://github.com/jusso-dev/Bower/issues/154).
The bounded generators slowed with request latency, so the achieved rates measure
the whole lab configuration, not an isolated collector maximum.

The console smoke test showed all six collectors, five behind a relay, redaction
counts and a clear “not proven yet” Sentinel status. Development administration
stayed on loopback through an SSM tunnel; production Entra login was not tested.

## Read the scope before using a score

Windows inputs were actual Application log events through a signed test pack.
The host labelled `Wec` did not have WEF/WEC forwarding configured. Original
source Computer preservation remains unverified. Linux load used semantic HTTP
input rather than journald, auditd or syslog.

The campaign used two 60-second load steps. It did not run the full privacy corpus,
30-minute load steps, long soak, packet-loss, power-loss, tamper, upgrade, uninstall,
credential-rotation or bad-policy-push scenarios from
[#136](https://github.com/jusso-dev/Bower/issues/136). The issue remains open.

The harness exports IDs, counts, timings and verdicts. Seed values, credentials,
raw queue data and source payloads stay inside the lab. Teardown deletes the
instances, disks, network endpoints, NAT gateway, Elastic IP and lab secrets;
only private reports/artifacts with a 90-day lifecycle are retained. Always inspect
the generated cleanup report. A scheduled expiry guard is only a backup.
