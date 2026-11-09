# Decision: Windows Event Forwarding via a WEC host first

Status: accepted (27-10-2026, recorded 09-11-2026). Issue: #91.

## Context

Windows hosts can forward events with Windows Event Forwarding (WEF), which is built into
Windows: clients read a subscription manager address from Group Policy and push events over
WinRM to a collector. Bower needs a short allow-list of channels and event IDs from those
hosts, redacted and selected by default-deny policy before anything is persisted. It must not
need an agent on every Windows machine.

## Options

| | (a) Native WEF endpoint in Bower | (b) Windows Server WEC host plus Bower |
|---|---|---|
| What runs where | Bower implements the WS-Management and WS-Eventing collector, so it can run on Linux | The built-in Windows Event Collector service receives into `ForwardedEvents`; the Bower collector on the same host reads that channel |
| New protocol surface | SOAP over HTTPS, Kerberos and SPNEGO, client certificate mapping, the subscription manager protocol, per-client bookmarks | None: the reader uses the event log API Bower already ships |
| Authentication | Bower owns Kerberos and certificate validation | Windows owns them (WinRM HTTPS on 5986, Kerberos or mapped client certificates) |
| Supportability | A Bower-only implementation of a Microsoft protocol | A supported Microsoft stack, documented by Microsoft |
| Code in Bower today | None | `src/Bower.Source.WindowsEventLog` (allow-list, durable bookmarks, group commit) |
| Residual risk | Bower handles unauthenticated network input | `ForwardedEvents` holds unredacted events on the WEC host until Bower reads them |

## Decision

Ship (b) first. The WEC host runs the C# collector with the
[Windows Event Log source](../deployment/windows-event-log-source.md) on `ForwardedEvents`.
`bower wec subscription generate` writes the source-initiated subscription from the same
validated allow-list the collector uses, so forwarders select at source exactly what the
collector accepts, and the collector still enforces the allow-list and the pack parser.

(a) stays a follow-on (#213). Revisit it once (b) is proven in the lab (#136) and there is a real
need for a Linux-only collector in a Windows estate.

## Consequences

- One hardened Windows Server per 2,000-4,000 forwarders; larger estates add WEC hosts.
- The WEC host is a high-value system: restrict the `ForwardedEvents` ACL, bound its size,
  and run the collector as a least-privilege account (see the
  [deployment guide](../deployment/windows-event-forwarding.md)).
- Bower does not see per-forwarder WinRM state directly. `wecutil gr` runtime status is the
  source of truth until the collector reports it.
