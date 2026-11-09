# Windows Event Forwarding to a Bower WEC host

Use this when many Windows hosts need to send a short list of security events and you don't
want an agent on each one. The hosts forward with built-in Windows Event Forwarding (WEF) to
one Windows Server running the Windows Event Collector (WEC) service and the Bower collector.
The collector reads `ForwardedEvents` with the [Windows Event Log
source](windows-event-log-source.md). Why this design: [decision record](../architecture/windows-event-forwarding-decision.md).

```text
member servers ──WinRM HTTPS 5986──▶ WEC host: ForwardedEvents ──▶ Bower collector ──▶ Sentinel
 (GPO: subscription manager)          (source-initiated subscription)   allow-list, pack parser,
                                                                        redact, policy, queue
```

## 1. Write the collector subscription and the WEF subscription from one allow-list

Write the collector's `BOWER_WINDOWS_EVENTLOG_CONFIG` with a subscription on
`ForwardedEvents` (see [configure](windows-event-log-source.md#configure)), for example:

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "WindowsEventLogSource",
  "subscriptions": [
    {
      "id": "security-logon",
      "channel": "ForwardedEvents",
      "eventIds": [4625],
      "providers": ["Microsoft-Windows-Security-Auditing"],
      "pack": "windows-security-logon",
      "parser": 0
    }
  ]
}
```

The forwarders need to read the source channel (`Security`), not `ForwardedEvents`, so keep a
second file with the same subscription and `"channel": "Security"`, and generate the WEF
subscription from it:

```bash
bower wec subscription generate --config wef-sources.json --subscription security-logon --out security-logon.xml
```

The output is a source-initiated subscription with:

- one `Select` built from the validated event IDs and providers: the same XPath the collector
  uses, without a record position. There is no free-text query and no collect-all form;
- `TransportName` `HTTPS`, so forwarders use WinRM on 5986;
- `ContentFormat` `Events` (no rendered message strings travel; the collector renders them
  only when its subscription sets `includeMessage`);
- `ConfigurationMode` `MinLatency` (about 30-second batches), `LogFile` `ForwardedEvents`,
  `ReadExistingEvents` `false`;
- `AllowedSourceDomainComputers` `O:NSG:NSD:(A;;GA;;;DC)` (Domain Computers).

| Option | Use |
|---|---|
| `--mode Normal` or `MinBandwidth` | Batching of about 15 minutes or 6 hours, for low-priority channels |
| `--mode Custom --max-items N --max-latency-seconds N` | Explicit batching |
| `--heartbeat-seconds N` | Forwarder heartbeat, default 900 (60 to 86400) |
| `--issuer-ca THUMBPRINT` | Accept certificate-authenticated forwarders whose client certificate this CA issued (repeat for up to 16 CAs) |
| `--allowed-domain-computers SDDL` | Narrow which domain computers may forward, for example a security group SID |
| `--read-existing` | Forward events already in the channel when a host first subscribes |

Then on the WEC host:

```powershell
wecutil qc /q
wecutil cs .\security-logon.xml
wecutil gs bower-security-logon
```

## 2. Point the forwarders at the WEC host

Group Policy: *Computer Configuration > Administrative Templates > Windows Components > Event
Forwarding > Configure target Subscription Manager*, enabled, with:

```text
Server=https://wec01.corp.example:5986/wsman/SubscriptionManager/WEC,Refresh=600
```

Add `,IssuerCA=<thumbprint of the CA that issued the WEC server certificate>` for
certificate-authenticated forwarders. Scope the GPO by OU or security group to spread
forwarders across WEC hosts.

To forward the Security log, the forwarder's Network Service account needs read access:
add `NETWORK SERVICE` to *Event Log Readers* on the forwarders, or set the Security channel
access string through Group Policy to include `(A;;0x1;;;S-1-5-20)`.

## 3. WinRM over HTTPS on the WEC host

- A server authentication certificate whose subject is the WEC host's FQDN, in the local
  machine Personal store, and an HTTPS listener for it:
  `winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname="<fqdn>";CertificateThumbprint="<thumbprint>"}'`
- Open TCP 5986 to the forwarder networks only. Don't open 5985.
- **Domain-joined forwarders** authenticate with Kerberos.
- **Workgroup and DMZ forwarders** use a client authentication certificate (subject = the
  host's FQDN) from an internal CA. On the WEC host, enable certificate auth
  (`winrm set winrm/config/service/auth '@{Certificate="true"}'`) and map the issuing CA
  (`winrm create winrm/config/service/certmapping?Issuer=<CA thumbprint>+Subject=*+URI=*`).
  On each forwarder, grant `NETWORK SERVICE` read on the client certificate's private key.
  Generate the subscription with `--issuer-ca <CA thumbprint>`. Rotate client certificates
  before expiry, and revoke a lost host's certificate at the CA (the WEC host checks
  revocation).

## 4. Size and protect `ForwardedEvents`

- Size it so the longest planned Bower outage doesn't wrap the log: 1 to 4 GB is typical.
  `wevtutil sl ForwardedEvents /ms:4294967296`. See [WEC sizing](windows-event-log-source.md#throughput-cpu-and-wec-sizing).
- `ForwardedEvents` holds **unredacted** events until Bower reads them. Restrict its channel
  access to administrators, the event log service and the collector account, and keep the
  WEC host hardened.
- Run the collector as a least-privilege account in *Event Log Readers*
  ([least privilege](windows-event-log-source.md#run-with-least-privilege)).

## 5. Check it

| Check | How |
|---|---|
| Subscription present and enabled | `wecutil gs bower-security-logon` |
| Forwarders connected | `wecutil gr bower-security-logon` lists each source with its state and last heartbeat |
| Bower is reading | `GET /v1/status`: `windowsEventLog[]` for the subscription is `running`, `lastPollAt` moves |
| Listener and certificate | `winrm e winrm/config/listener`, and the certificate's expiry date |
| Events arrive | `bower tap --stage redacted --source <pack application>` while a test event is raised on a forwarder |

## Not done yet

These parts of #91 need the Windows lab (#136) or more code, and aren't claimed here:

- An end-to-end GPO plus Kerberos run, and a certificate-authenticated workgroup run.
- Reporting `wecutil gr` runtime status in `/v1/status` and the heartbeat.
- `bower doctor` checks on the WEC host (service, subscription, listener, `ForwardedEvents` fill).
- A per-subscription silence alarm independent of event rate: today use `lastPollAt` and
  `state`, and source expectations for steady application events.
