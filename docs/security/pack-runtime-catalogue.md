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

`linux-journald-ssh` 1.0.1 exposes one signed JSON parser (index 0) for systemd
journal JSON export records (`journalctl -o json`). Its transform program extracts
account, source address and method from an sshd `MESSAGE` with a bounded regex, keeps
only `SYSLOG_IDENTIFIER` `sshd`, maps the method through a static table to the outcome
reason and converts `__REALTIME_TIMESTAMP` (microseconds) to UTC. It produces only
`authentication_failure`, action `authentication.attempt`, result `failure`,
application `linux-sshd`, environment `production`, original ID `__CURSOR`. Policy
`BWR-PACK-JOURNALD-SSH-AUTH` 1.0.0 selects; usernames are pseudonymised. `MESSAGE`,
host name and other journal fields are never forwarded. A binary (array) `MESSAGE` is
quarantined with `transform-type-error`. Version 1.0.1 only adds `expectFields`
assertions to its samples; parser, policy and privacy profile are unchanged.

`linux-authlog-ssh` 1.3.0 exposes one signed JSON parser (index 0) for plain-text sshd
`auth.log` lines from the [file tail source](../deployment/file-tail-source.md). Its
transform program matches the whole line with an exact grammar: an RFC 3339 or classic
syslog time (impossible dates refused), the `sshd[pid]` or `sshd-session[pid]` tag, and
`Failed <method> for [invalid user ]<user> from <ip> port <n> ssh2`. `password`,
`keyboard-interactive/pam`, `none` and `gssapi-with-mic` must end there; `publickey` must end
with exactly a key (optionally a certificate with its key ID, serial and CA key), except
that an invalid user's public key failure may end without one. The address may carry an
IPv6 scope of at most 15 safe characters, which is not reported. The username and the
certificate key ID, the two client-controlled fields, may not contain spaces, so neither can
move the reported source address. Not selected: `hostbased` (its trailer carries a
client-chosen user and host) and any other method, usernames or key IDs with spaces, key
suffixes on keyless methods, a valid user's keyless public key failure, `message repeated`,
`Invalid user`, `Connection closed`, `Disconnected`, `maximum authentication attempts`,
pam_unix and `Accepted` lines, other programs and lines without a parseable time. It maps
the method through a static table to the outcome reason and converts the time to UTC
(classic times are read as UTC in the evaluation year); the read time is never
substituted. It produces only `authentication_failure`, action `authentication.attempt`,
result `failure`, application `linux-sshd`, environment `production`, original ID the file
source's `file-` id. Policy `BWR-PACK-AUTHLOG-SSH-AUTH` 1.0.0 selects; usernames are
pseudonymised. The line, host name and file path are never forwarded. Version 1.3.0 adds the
keyless `none`, `gssapi-with-mic` and invalid-user public key forms and scoped IPv6
addresses; 1.2.0 replaced 1.1.0's end-anchored match with the exact grammar. The policy and
privacy profile are unchanged.

`windows-security-logon` 1.0.2 exposes one signed JSON parser (index 0) for records from
the [Windows Event Log source](../deployment/windows-event-log-source.md), subscribed
to Security event 4625 only. Its transform program explicitly requires the `Security`
channel even if a subscription binds the pack to another channel, and keeps only provider
`Microsoft-Windows-Security-Auditing` events with `data.LogonType` equal to `3` (network)
and a source address (`data.IpAddress`
must be an address; local console failures with `-` are not selected) and maps the
NTSTATUS `data.SubStatus`, then `data.Status`, through a static table to the outcome
reason (`InvalidCredentials`, `UnknownAccount`, `AccountLockedOut`, `AccountDisabled`,
`AccountExpired`, `PasswordExpired`, `PasswordChangeRequired`, `OutsideLogonHours`,
`WorkstationRestricted`, `LogonTypeNotGranted`, `ClockSkew`, `AuthenticationFirewall`,
otherwise `OtherFailure`). It produces only `authentication_failure`, action
`authentication.attempt`, result `failure`, application `windows-security`, environment
`production`, original ID the source's `winevt-` id. Policy
`BWR-PACK-WIN-LOGON-FAILURE` 1.0.0 selects; usernames (`data.TargetUserName`) are
pseudonymised. Workstation, domain, logon process, computer and the rest of
`EventData` are never forwarded.

Version 1.0.2 narrows selection from 1.0.1: interactive logons and other logon types,
including a missing type, are no longer selected even if they carry a valid source
address. The failure policy and privacy profile are unchanged. Rejection samples cover
interactive loopback logons and missing logon types.

Other parser configurations without a signed runtime mapping are preview-only.
Cloud packs use their existing semantic agent paths and local detections; no new
cloud raw parser is activated here. DCR templates remain packaged-only.

See [activation, limits, failure codes and Sigma subset](../deployment/packs.md#local-parser-and-detection-activation).
All host demonstrations are local and synthetic. Destination delivery requires a
separate authorised query; no Sentinel delivery or all-software coverage is claimed.
