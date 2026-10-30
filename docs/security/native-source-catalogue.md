# Native source event catalogue

| Source | Selection | Envelope | Privacy |
| --- | --- | --- | --- |
| Windows Security / WEC ForwardedEvents | Provider Microsoft-Windows-Security-Auditing, event 4625, network logon type 3, valid source address | authentication_failure; windows-security application; normalized failure reason | Username HMAC; domain, workstation, process and unrelated EventData excluded |
| Syslog RFC 3164/5424 | Sender allow-list, first matching route, trusted signed runtime parser and policy | Only the event type declared by that parser; no generic raw-log envelope | Existing privacy engine before durable enqueue |

The Windows mapping ships in `packs/windows-security-logon` version 1.0.2.
Syslog transport alone selects no security semantics. A firewall or appliance
requires its own scoped signed parser and policy. Both sources reject unknown
and malformed input. They do not bypass existing authentication or privacy rules.
