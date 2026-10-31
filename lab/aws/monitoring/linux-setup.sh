#!/bin/bash
# Installs the drill's Linux collector (systemd), the rsyslog mutual-TLS firewall sender, the
# nftables deny fixture, the 1/sec packet generator and the health-check timer.
# Fetches lab material from the run's private bucket; prints no secret values.
set -euo pipefail
trap 'echo "linux-setup failed at line $LINENO" >&2' ERR
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}"
dnf -y -q install rsyslog rsyslog-openssl nftables python3 sqlite >/dev/null
id bower >/dev/null 2>&1 || useradd --system --home-dir /var/lib/bower --shell /sbin/nologin bower
stage=$(mktemp -d)
aws s3 cp --quiet --recursive "s3://$BOWER_LAB_BUCKET/artifacts/linux/" "$stage/"
install -d -m 0755 /opt/bower /opt/bower/monitoring /opt/bower-cli
# The package creates the spool directory; bower.service lists it in ReadWritePaths.
install -d -m 0750 -o bower -g bower /var/spool/bower
systemctl stop bower.service bower-fw-generator.service >/dev/null 2>&1 || true
rm -rf /opt/bower/* /opt/bower-cli/* /etc/bower/policies
install -d -m 0755 /opt/bower/monitoring
tar -xzf "$stage/collector.tar.gz" -C /opt/bower --strip-components=1
tar -xzf "$stage/cli.tar.gz" -C /opt/bower-cli --strip-components=1
chmod 0755 /opt/bower/Bower.Collector /opt/bower-cli/bower
install -d -m 0750 -o root -g bower /etc/bower /etc/bower/secrets /etc/bower/packs /etc/bower/keys /etc/bower/syslog
tar -xzf "$stage/policies.tar.gz" -C /etc/bower
chown -R root:bower /etc/bower/policies; chmod 0750 /etc/bower/policies; chmod 0640 /etc/bower/policies/*
install -m 0640 -o root -g bower "$stage/bower.env" /etc/bower/bower.env
install -m 0640 -o root -g bower "$stage/ingest-token" /etc/bower/secrets/ingest-token
install -m 0640 -o root -g bower "$stage/ingest.pem" /etc/bower/secrets/ingest.pem
install -m 0640 -o root -g bower "$stage/nftables-validation-1.0.0.bowerpack" /etc/bower/packs/
install -m 0640 -o root -g bower "$stage/pack-signing.pub.pem" /etc/bower/keys/pack-signing.pub.pem
install -m 0640 -o root -g bower "$stage/syslog.json" "$stage/source-expectations.json" /etc/bower/
install -m 0640 -o root -g bower "$stage/server.pem" /etc/bower/syslog/server.pem
install -m 0640 -o root -g bower "$stage/server-key.pem" /etc/bower/syslog/server-key.pem
install -m 0640 -o root -g bower "$stage/ca.pem" /etc/bower/syslog/ca.pem
install -m 0644 "$stage/bower.service" /etc/systemd/system/bower.service
install -d -m 0755 /etc/systemd/system/bower.service.d
install -m 0644 "$stage/bower-monitoring.conf" /etc/systemd/system/bower.service.d/10-monitoring.conf
install -m 0755 "$stage/bower-healthcheck.py" /opt/bower/monitoring/bower-healthcheck.py
install -m 0644 "$stage/bower-healthcheck.service" "$stage/bower-healthcheck.timer" /etc/systemd/system/
install -m 0755 "$stage/replay.py" /opt/bower/monitoring/replay.py
# rsyslog sender (lab-only client certificate).
install -d -m 0700 /etc/bower-lab/syslog
install -m 0600 "$stage/ca.pem" /etc/bower-lab/syslog/ca.pem
install -m 0600 "$stage/client.pem" /etc/bower-lab/syslog/client.pem
install -m 0600 "$stage/client-key.pem" /etc/bower-lab/syslog/client-key.pem
install -m 0644 "$stage/20-bower-firewall.conf" /etc/rsyslog.d/20-bower-firewall.conf
if ! grep -q 'Ratelimit.Burst="200000"' /etc/rsyslog.conf; then
  sed -i 's/^module(load="imjournal"/module(load="imjournal" Ratelimit.Interval="600" Ratelimit.Burst="200000"/' /etc/rsyslog.conf
fi
rsyslogd -N1 >/dev/null
rm -rf "$stage"
# nftables deny fixture: packets to the TEST-NET-1 sink are logged and dropped.
nft list table inet bower_validation >/dev/null 2>&1 || {
  nft add table inet bower_validation
  nft add chain inet bower_validation out '{ type filter hook output priority 0; policy accept; }'
  nft add rule inet bower_validation out ip daddr 192.0.2.10 udp dport 9 log prefix '"BOWER_DENY "' drop
}
cat > /usr/local/bin/bower-fw-generator <<'GEN'
#!/usr/bin/python3
import socket, time
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    try:
        sink.sendto(b"x", ("192.0.2.10", 9))
    except PermissionError:
        pass  # the nftables rule logs and drops the packet: that is the point
    time.sleep(1)
GEN
chmod 0755 /usr/local/bin/bower-fw-generator
cat > /etc/systemd/system/bower-fw-generator.service <<'UNIT'
[Unit]
Description=Bower drill: one denied packet per second
[Service]
ExecStart=/usr/local/bin/bower-fw-generator
DynamicUser=yes
UNIT
systemctl daemon-reload
systemctl reset-failed bower.service >/dev/null 2>&1 || true
systemctl enable --now bower.service >/dev/null 2>&1
for attempt in $(seq 1 30); do curl -fsS http://127.0.0.1:4319/health >/dev/null 2>&1 && break; sleep 2; done
systemctl enable --now rsyslog.service >/dev/null 2>&1; systemctl restart rsyslog.service
systemctl enable --now bower-healthcheck.timer >/dev/null 2>&1
systemctl start bower-fw-generator.service
sleep 20
echo "collector: $(systemctl is-active bower) rsyslog: $(systemctl is-active rsyslog) generator: $(systemctl is-active bower-fw-generator) timer: $(systemctl is-active bower-healthcheck.timer)"
curl -fsS http://127.0.0.1:4319/health; echo
sha256sum /opt/bower/Bower.Collector /opt/bower/Bower.Collector.dll /opt/bower-cli/bower /etc/bower/packs/*.bowerpack | sed 's|  | |'
token=$(cat /etc/bower/secrets/ingest-token)
curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; s=json.load(sys.stdin); print(json.dumps({"status":s["status"],"queue":s["queue"],"syslog":[{k:l[k] for k in ("id","activeConnections","connectionsAccepted","framesReceived","queued","tlsHandshakeFailures")} for l in s.get("syslog") or []],"sources":s.get("sources")}))'
