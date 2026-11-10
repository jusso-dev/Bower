#!/usr/bin/env bash
# Runs as root in the Rocky Linux 9 systemd container after the rpm is installed (#245).
# Switches the packaged service to BOWER_OUTPUT=syslog and checks, with the real collector,
# the packaged unit's sandbox and journald on /dev/log:
#   1. bower test emit: one bower-b64: line in the journal that decodes to the event;
#   2. a burst of 2,000 events: every one is acknowledged by the collector and every one is
#      in the journal within 120 seconds.
# Then restores the settings. Never prints a token.
set -euo pipefail

# On failure print the unit's own messages, never the bower-tagged event lines.
fail() { echo "FAIL: $*" >&2; journalctl -u bower.service -t Bower.Collector --no-pager -n 40 -o cat 2>/dev/null | grep -v 'bower-b64:' >&2 || true; exit 1; }
env_file=/etc/bower/bower.env
cp -p "$env_file" /root/bower.env.before
listener=""
restore() {
  [ -z "$listener" ] || kill "$listener" 2>/dev/null || true
  rm -f /etc/rsyslog.d/10-bower-forward-test.conf
  cp -p /root/bower.env.before "$env_file"
  rm -f /etc/bower/producer-scopes.json /etc/systemd/system/bower.service.d/syslog-output.conf
  systemctl daemon-reload
  systemctl restart bower.service || true
}
trap restore EXIT

# journald's per-unit limit would otherwise drop part of the burst (the guide's drop-in).
install -d /etc/systemd/system/bower.service.d
printf '[Service]\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=50000\n' \
  > /etc/systemd/system/bower.service.d/syslog-output.conf
# Producer scopes are default deny: grant the loopback producer the canary and burst identities,
# as the quick start's step 5 does.
host="$(cat /proc/sys/kernel/hostname)"
cat > /etc/bower/producer-scopes.json <<JSON
[
  {"producer": "anonymous", "application": {"name": "BowerCanary", "environment": "test", "instance": "$host"},
   "source": {"ipAddress": "192.0.2.1"}},
  {"producer": "anonymous", "application": {"name": "BowerBurst", "environment": "test"},
   "source": {"ipAddress": "192.0.2.1"}}
]
JSON
chown root:bower /etc/bower/producer-scopes.json
chmod 0640 /etc/bower/producer-scopes.json
printf 'BOWER_OUTPUT=syslog\nBOWER_SYSLOG_OUTPUT_FACILITY=local4\nBOWER_PRODUCER_SCOPES_FILE=/etc/bower/producer-scopes.json\n' >> "$env_file"
systemctl daemon-reload
systemctl restart bower.service
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:4319/health >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.1:4319/health >/dev/null || fail "collector did not come back with BOWER_OUTPUT=syslog"
bower doctor --syslog-socket /dev/log --policy-directory /etc/bower/policies | grep -q '^PASS  syslog' \
  || fail "bower doctor did not pass the syslog socket check"

decoded_ids() {
  journalctl -t bower -o cat --no-pager -q | sed -n 's/^bower-b64:\(.*\)$/\1/p' \
    | while read -r b64; do printf '%s' "$b64" | base64 -d | python3 -c 'import json,sys; print(json.load(sys.stdin)["eventId"])'; done
}

# 1. One event through the packaged service.
response="$(bower test emit)"
event_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["eventId"])' "$response")"
for _ in $(seq 1 30); do
  decoded_ids | grep -qxF "$event_id" && break
  sleep 1
done
decoded_ids | grep -qxF "$event_id" || fail "event $event_id is not in the journal as a bower-b64: line"
echo "syslog output: bower test emit reached the journal and decodes to the event"

# 2. A burst of 2,000 events, posted as fast as the collector takes them.
python3 - <<'PYTHON'
import json, urllib.request, uuid, datetime
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
ids = []
for index in range(2000):
    event_id = str(uuid.uuid4())
    ids.append(event_id)
    body = json.dumps({
        "schemaVersion": "1.0.0", "eventId": event_id, "timeGenerated": now,
        "eventCategory": "authentication", "eventType": "authentication_failure",
        "eventAction": "authentication.attempt", "eventResult": "failure",
        "eventOutcomeReason": "SyntheticInvalidPassword",
        "application": {"name": "BowerBurst", "environment": "test"},
        "actor": {"username": "burst-user"}, "source": {"ipAddress": "192.0.2.1"},
        "request": {"correlationId": f"burst-{index}"}
    }).encode()
    request = urllib.request.Request("http://127.0.0.1:4319/v1/events", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as response:
        assert response.status in (200, 202), response.status
open("/root/burst-ids", "w").write("\n".join(ids) + "\n")
PYTHON
deadline=$((SECONDS + 120))
while :; do
  arrived="$(decoded_ids | grep -cxF -f /root/burst-ids || true)"
  [ "$arrived" -ge 2000 ] && break
  [ "$SECONDS" -lt "$deadline" ] || fail "only $arrived of 2000 burst events reached the journal in 120 s"
  sleep 2
done
status="$(curl -sf http://127.0.0.1:4319/v1/status)"
python3 - "$status" <<'PYTHON' || fail "collector status after the burst is not clean"
import json, sys
status = json.loads(sys.argv[1])
queue = status["queue"]
assert status["output"] == "syslog", status["output"]
assert queue["deadLettered"] == 0, queue
assert queue["retrying"] == 0, queue
PYTHON
echo "syslog output: 2000 of 2000 burst events acknowledged and in the journal"

# 3. rsyslog forwards the largest event Bower accepts whole (#230, #245 test 4). A local TCP
#    listener stands in for Azure Monitor Agent's forward. Event content is never printed.
if command -v dnf >/dev/null; then dnf install -y -q rsyslog >/dev/null; else apt-get install -y -qq rsyslog >/dev/null; fi
python3 - >/root/forward-listener.log 2>&1 <<'PYTHON' &
import socket
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 28330))
server.listen(4)
with open("/root/forwarded", "ab") as out:
    while True:
        connection, _ = server.accept()
        while chunk := connection.recv(65536):
            out.write(chunk)
            out.flush()
PYTHON
listener=$!
for _ in $(seq 1 20); do
  (exec 3<>/dev/tcp/127.0.0.1/28330) 2>/dev/null && break
  sleep 0.5
done
printf 'local4.* action(type="omfwd" target="127.0.0.1" port="28330" protocol="tcp")\n' \
  > /etc/rsyslog.d/10-bower-forward-test.conf
systemctl restart rsyslog
sleep 2
# The collector adds its own context to the envelope (its size depends on the collector id
# and settings). Aim for about 5,400 bytes of JSON, below the 5,730 that fits the default
# 7,680-byte message with room for that context, and well above rsyslog's old risk zone.
large_id="$(python3 - <<'PYTHON'
import json, urllib.request, uuid, datetime
event_id = str(uuid.uuid4())
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
event = {"schemaVersion": "1.0.0", "eventId": event_id, "timeGenerated": now,
         "eventCategory": "authentication", "eventType": "authentication_failure",
         "eventAction": "authentication.attempt", "eventResult": "failure",
         "eventOutcomeReason": "x" * 1000,
         "application": {"name": "BowerBurst", "environment": "test"},
         "actor": {"username": "burst-user"}, "source": {"ipAddress": "192.0.2.1"},
         "request": {"correlationId": "large"},
         "attributes": {"note": "y" * 3250}}
request = urllib.request.Request("http://127.0.0.1:4319/v1/events", json.dumps(event).encode(), {"Content-Type": "application/json"})
urllib.request.urlopen(request).read()
print(event_id)
PYTHON
)"
# On a fresh install imjournal starts at the beginning of the journal and replays the burst
# above before this event: allow it time on a slow runner.
forward_ok=0
python3 - "$large_id" <<'PYTHON' || forward_ok=$?
import base64, json, re, sys, time
want = sys.argv[1]
deadline = time.time() + 240
while time.time() < deadline:
    try:
        forwarded = open("/root/forwarded", "rb").read().decode(errors="replace")
    except FileNotFoundError:
        forwarded = ""  # rsyslog has not connected to the listener yet
    for line in forwarded.splitlines():
        match = re.search(r"bower-b64:([A-Za-z0-9+/]+={0,2})\s*$", line)
        if not match:
            continue
        try:
            envelope = json.loads(base64.b64decode(match.group(1)))
        except ValueError:
            continue
        if envelope.get("eventId") == want:
            size = len(json.dumps(envelope, separators=(",", ":")).encode())
            print(f"syslog output: rsyslog forwarded a {len(line)}-character line that decodes ({size} bytes of JSON)")
            sys.exit(0)
    time.sleep(1)
sys.exit(1)
PYTHON
if [ "$forward_ok" -ne 0 ]; then
  # Metadata only: sizes, counts and rsyslog's own messages, never event content.
  echo "forwarded bytes: $(stat -c %s /root/forwarded 2>/dev/null || echo none); listener: $(cat /root/forward-listener.log 2>/dev/null)" >&2
  journalctl -u rsyslog --no-pager -n 15 -o cat 2>/dev/null | grep -v 'bower-b64:' >&2 || true
  curl -sf http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; s=json.load(sys.stdin); print("queue", s["queue"], "last failure", s["deliveryActivity"]["lastFailureCode"])' >&2 || true
  fail "the forwarded line for the large event was not whole"
fi
kill "$listener" 2>/dev/null || true
rm -f /etc/rsyslog.d/10-bower-forward-test.conf /root/forwarded
systemctl restart rsyslog
