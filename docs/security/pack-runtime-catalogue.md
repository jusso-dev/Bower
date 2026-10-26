# Pack runtime event catalogue

`linux-ssh-gateway` 1.1.0 exposes one signed JSON parser (index 0). The source
contract is normalized SSH/PAM JSON, with stable original ID, offset timestamp,
username, source IP and exact result `failure`. It produces only
`authentication_failure`, action `authentication.attempt`, result `failure`,
application `ssh-gateway`, environment `production`. Unknown actions stay denied.

Existing `BWR-PACK-SSH-AUTH` 1.0.0 selects eligible events. The pack privacy profile
pseudonymises usernames before persistence. Local rule
`bower-pack-ssh-auth-failure-001` 1.0.0 attaches stable rule hash/version and T1110
metadata to the accepted semantic row. It does not assert an observed password
spray aggregate; matching is per event. Unmapped raw fields are discarded.
Selected events with ambiguous or over-limit detection fields are quarantined
with `pack-detection-failed` before source persistence; they cannot bypass local
detections by adding unrelated labels or attributes. Producer evidence is removed
before evaluation and replaced only by locally computed `bowerDetections`.

`linux-journald-ssh` 1.0.0 exposes one signed JSON parser (index 0) for systemd
journal JSON export records (`journalctl -o json`). Its transform program extracts
account, source address and method from an sshd `MESSAGE` with a bounded regex, keeps
only `SYSLOG_IDENTIFIER` `sshd`, maps the method through a static table to the outcome
reason and converts `__REALTIME_TIMESTAMP` (microseconds) to UTC. It produces only
`authentication_failure`, action `authentication.attempt`, result `failure`,
application `linux-sshd`, environment `production`, original ID `__CURSOR`. Policy
`BWR-PACK-JOURNALD-SSH-AUTH` 1.0.0 selects; usernames are pseudonymised. `MESSAGE`,
host name and other journal fields are never forwarded. A binary (array) `MESSAGE` is
quarantined with `transform-type-error`.

Other parser configurations without a signed runtime mapping are preview-only.
Cloud packs use their existing semantic agent paths and local detections; no new
cloud raw parser is activated here. DCR templates remain packaged-only.

See [activation, limits, failure codes and Sigma subset](../deployment/packs.md#local-parser-and-detection-activation).
All host demonstrations are local and synthetic. Destination delivery requires a
separate authorised query; no Sentinel delivery or all-software coverage is claimed.
