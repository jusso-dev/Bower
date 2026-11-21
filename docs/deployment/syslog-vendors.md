# Syslog vendor configuration guides

These guides configure common Linux daemons and network security appliances to forward
security events to Bower's [syslog source](syslog-source.md) over **RFC 5424 TLS**
(`TCP/6514`). All hostnames and addresses below are synthetic (`192.0.2.x`,
`bower-collector.example.gov.au`).

Never send raw unrestricted debug traffic to Bower: configure each appliance to forward
only security-relevant facilities (authentication, firewall denies, threat, and
configuration changes) and pair every listener with a signed Bower pack parser.

## 1. Linux rsyslog (RFC 5424 over TLS)

Install `rsyslog-gnutls` (or `rsyslog-openssl`), place the collector's CA bundle at
`/etc/ssl/certs/bower-ca.pem`, and create `/etc/rsyslog.d/60-bower-security.conf`:

```text
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/ssl/certs/bower-ca.pem"
)

# Forward only authentication and security facilities with a bounded disk-assisted queue.
auth,authpriv.* action(
  type="omfwd"
  target="bower-collector.example.gov.au"
  port="6514"
  protocol="tcp"
  template="RSYSLOG_SyslogProtocol23Format"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="bower-collector.example.gov.au"
  queue.type="LinkedList"
  queue.filename="bower_fwd"
  queue.maxDiskSpace="256m"
  queue.saveOnShutdown="on"
  action.resumeRetryCount="-1"
)
```

Validate with `rsyslogd -N1` and restart `rsyslog`.

## 2. Linux syslog-ng (RFC 5424 over TLS)

Add `/etc/syslog-ng/conf.d/60-bower.conf`:

```text
filter f_bower_security {
  facility(auth, authpriv) or program("sshd") or program("sudo");
};

destination d_bower_tls {
  syslog(
    "bower-collector.example.gov.au"
    port(6514)
    transport("tls")
    tls(
      ca-dir("/etc/syslog-ng/ca.d")
      peer-verify(required-trusted)
    )
    disk-buffer(
      mem-buf-size(10485760)
      disk-buf-size(268435456)
      reliable(yes)
    )
  );
};

log {
  source(s_src);
  filter(f_bower_security);
  destination(d_bower_tls);
};
```

Validate with `syslog-ng --syntax-only` and reload `syslog-ng`.

## 3. Palo Alto Networks PAN-OS

1. **Import the collector CA certificate:** *Device → Certificate Management → Certificates
   → Import* (`bower-ca.pem`). Create a *Certificate Profile* referencing it.
2. **Create a Syslog Server Profile:** *Device → Server Profiles → Syslog → Add*:
   - Name: `Bower-Syslog-TLS`
   - Syslog Server: `bower-collector.example.gov.au`
   - Transport: **SSL** (TLS), Port: `6514`
   - Format: **IETF** (RFC 5424), Facility: `LOG_USER`
3. **Create a Log Forwarding Profile:** *Objects → Log Forwarding → Add* and forward only
   **Threat**, **Authentication**, **System**, and **Config** logs (plus security-relevant
   **Traffic** denies) to `Bower-Syslog-TLS`.
4. Commit the configuration and verify receipt on the collector with `bower top`.

## 4. Fortinet FortiGate (FortiOS)

Configure RFC 5424 over TLS on the FortiGate CLI (replace `Bower_CA` with the imported CA
certificate name):

```text
config log syslogd setting
    set status enable
    set server "bower-collector.example.gov.au"
    set mode reliable
    set port 6514
    set format rfc5424
    set enc-algorithm high
    set ssl-min-proto-version TLSv1-2
    set certificate "Bower_CA"
end

config log syslogd filter
    set severity warning
    set forward-traffic disable
    set local-traffic enable
    set anomaly enable
    set voip disable
end
```

## 5. Cisco IOS-XE / ASA

### Cisco IOS-XE (TCP / TLS via PKI trustpoint)

```text
logging trap informational
logging facility local6
logging source-interface Loopback0
logging host 192.0.2.10 transport tcp port 6514
logging origin-id hostname
service timestamps log datetime msec localtime show-timezone year
```

For TLS transport on IOS-XE releases supporting RFC 5425, attach a configured PKI
trustpoint (`transport tls`) or terminate TLS via a local rsyslog forwarder on the
management jump host.

### Cisco ASA

```text
logging enable
logging timestamp
logging trap notifications
logging facility 22
logging host management 192.0.2.10 6/6514 secure
```

## Verify with Bower

1. Confirm the listener is healthy in `/v1/status` (`syslog` block).
2. Watch post-redaction intake live with `bower tap --source syslog` or inspect counts with
   `bower top`.
3. Verify zero unapproved event types leak past default-deny policies.
