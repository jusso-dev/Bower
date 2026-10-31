#!/bin/bash
# Fault injection on the drill's Linux collector host. DRILL_ACTION selects one step; each
# prints the UTC time it took effect. Metadata only.
set -euo pipefail
: "${DRILL_ACTION:?}"
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
status() {
  local token; token=$(cat /etc/bower/secrets/ingest-token)
  curl -fsS -m 5 -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status | python3 -c '
import json,sys
s=json.load(sys.stdin); q=s["queue"]; i=s["intake"]
print(json.dumps({"status":s["status"],"queue":{k:q[k] for k in ("queued","retrying","uploading","delivered","deadLettered","undeliveredBytes","oldestUndelivered")},
 "intake":{k:i[k] for k in ("capacityRefusals","lastRefusalAt","lastRefusalReason")},
 "syslog":[{k:l[k] for k in ("activeConnections","connectionsAccepted","tlsHandshakeFailures","connectionsRejected","framesReceived","queued","retries")} for l in s.get("syslog") or []],
 "sources":[{k:x[k] for k in ("application","state","silentSeconds")} for x in s.get("sources") or []]}))'
}
case "$DRILL_ACTION" in
  stop-generator) systemctl stop bower-fw-generator; echo "fault $(now) generator stopped" ;;
  start-generator) systemctl start bower-fw-generator; echo "recovered $(now) generator started" ;;
  block-egress)
    # Blocks only the collector's HTTPS (Entra and Logs Ingestion); SSM runs as root and is unaffected.
    nft add rule inet bower_validation out meta skuid bower tcp dport 443 counter drop comment \"bower-drill-egress\"
    echo "fault $(now) collector HTTPS blocked" ;;
  unblock-egress)
    handle=$(nft -a list chain inet bower_validation out | awk '/bower-drill-egress/ {print $NF}')
    for h in $handle; do nft delete rule inet bower_validation out handle "$h"; done
    echo "recovered $(now) collector HTTPS restored" ;;
  burst)
    # DRILL_COUNT denied packets at DRILL_RATE per second, through the real nftables/rsyslog path.
    python3 - "${DRILL_COUNT:-4000}" "${DRILL_RATE:-200}" <<'PY'
import socket, sys, time
count, rate = int(sys.argv[1]), int(sys.argv[2])
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
start = time.monotonic()
for index in range(count):
    try:
        sink.sendto(b"x", ("192.0.2.10", 9))
    except PermissionError:
        pass
    delay = start + (index + 1) / rate - time.monotonic()
    if delay > 0:
        time.sleep(delay)
print(f"sent {count} packets in {time.monotonic() - start:.1f}s")
PY
    echo "burst-done $(now)" ;;
  tls-errors)
    # Unauthenticated TLS clients (no client certificate) and plain TCP: refused before acceptance.
    for i in $(seq 1 "${DRILL_COUNT:-5}"); do
      timeout 5 openssl s_client -connect 127.0.0.1:6514 -servername bower-collector </dev/null >/dev/null 2>&1 || true
      timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6514; printf "hello\n" >&3; sleep 1' >/dev/null 2>&1 || true
    done
    echo "fault $(now) ${DRILL_COUNT:-5} unauthenticated TLS and plain TCP attempts" ;;
  churn)
    for i in $(seq 1 "${DRILL_COUNT:-8}"); do systemctl restart rsyslog; sleep 3; done
    echo "fault $(now) rsyslog reconnected ${DRILL_COUNT:-8} times" ;;
  kill-collector)
    pid=$(systemctl show -p MainPID --value bower); kill -9 "$pid"; echo "fault $(now) SIGKILL $pid"
    for i in $(seq 1 60); do
      newpid=$(systemctl show -p MainPID --value bower)
      if [ "$newpid" != "0" ] && [ "$newpid" != "$pid" ] && curl -fsS -m 2 http://127.0.0.1:4319/health >/dev/null 2>&1; then
        echo "recovered $(now) systemd restarted the collector as $newpid"; break
      fi
      sleep 0.5
    done ;;
  stop-collector) systemctl stop bower; echo "fault $(now) collector stopped" ;;
  start-collector) systemctl start bower; for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4319/health >/dev/null 2>&1 && break; sleep 1; done; echo "recovered $(now) collector started" ;;
  set-attempts)
    sed -i '/^BOWER_MAX_DELIVERY_ATTEMPTS=/d' /etc/bower/bower.env
    [ -n "${DRILL_ATTEMPTS:-}" ] && echo "BOWER_MAX_DELIVERY_ATTEMPTS=$DRILL_ATTEMPTS" >> /etc/bower/bower.env
    systemctl restart bower; sleep 5; echo "configured $(now) attempts=${DRILL_ATTEMPTS:-default}" ;;
  healthcheck)
    systemctl start bower-healthcheck.service || true
    journalctl -u bower-healthcheck --no-pager -o short-iso -n "${DRILL_LINES:-6}" | grep -v "Starting\|Finished\|Deactivated\|Main process exited\|Failed with result\|Failed to start" || true ;;
  status) ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
status
