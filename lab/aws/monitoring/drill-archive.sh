#!/bin/bash
# Drill D7b: archive replay into a separate loopback-only replay collector with its own queue,
# wrapped in intent/outcome audit records. Metadata only.
set -euo pipefail
trap 'echo "drill-archive failed at line $LINENO" >&2' ERR
: "${DRILL_ACTION:?}"
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
case "$DRILL_ACTION" in
  enable-archive)
    install -d -m 0700 -o bower -g bower /var/lib/bower/archive
    sed -i '/^BOWER_ARCHIVE_PATH=/d' /etc/bower/bower.env
    echo 'BOWER_ARCHIVE_PATH=/var/lib/bower/archive' >> /etc/bower/bower.env
    systemctl restart bower
    echo "archive enabled $(now)" ;;
  archive-status)
    ls /var/lib/bower/archive | head -20
    /opt/bower-cli/bower archive verify --archive /var/lib/bower/archive | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({k:d[k] for k in d if k not in ("issues",)}))' ;;
  start-replay-collector)
    install -d -m 0700 -o bower -g bower /var/lib/bower/replay
    grep -v '^BOWER_COLLECTOR_ID=\|^BOWER_SYSLOG_CONFIG=\|^BOWER_SOURCE_EXPECTATIONS=\|^BOWER_HEALTH_RECORD_INTERVAL_SECONDS=\|^BOWER_ARCHIVE_PATH=\|^BOWER_MANAGEMENT_\|^BOWER_PRODUCER_SCOPES_FILE=\|^BOWER_QUEUE_MAX_BYTES=' /etc/bower/bower.env > /etc/bower/replay.env
    cat >> /etc/bower/replay.env <<'ENV'
BOWER_COLLECTOR_ID=ws6-linux-replay
BOWER_LISTEN_URL=http://127.0.0.1:4329
BOWER_QUEUE_PATH=/var/lib/bower/replay/queue.db
BOWER_QUEUE_MAX_BYTES=67108864
BOWER_SINGLE_TRUST_DOMAIN=true
ENV
    chown root:bower /etc/bower/replay.env; chmod 0640 /etc/bower/replay.env
    cat > /etc/systemd/system/bower-replay.service <<'UNIT'
[Unit]
Description=Bower replay collector (loopback only, own queue)
[Service]
Type=exec
User=bower
Group=bower
WorkingDirectory=/opt/bower
ExecStart=/opt/bower/Bower.Collector
EnvironmentFile=/etc/bower/replay.env
Environment=BOWER_POLICY_DIRECTORY=/etc/bower/policies
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/bower/replay
UNIT
    systemctl daemon-reload; systemctl restart bower-replay
    for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4329/health >/dev/null 2>&1 && break; sleep 1; done
    echo "replay collector $(systemctl is-active bower-replay) $(now)" ;;
  replay)
    : "${DRILL_FROM:?}" "${DRILL_TO:?}" "${DRILL_CHANGE:?}" "${DRILL_OPERATOR:?}"
    audit="/var/lib/bower-audit/$DRILL_CHANGE"
    install -d -m 0700 /var/lib/bower-audit; mkdir -m 0700 "$audit"
    verify=$(/opt/bower-cli/bower archive verify --archive /var/lib/bower/archive)
    head=$(echo "$verify" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in ("intact","segments","verifiedEvents","firstSequence","headSequence","headHash")}))')
    dry=$(/opt/bower-cli/bower archive replay --archive /var/lib/bower/archive --collector-url http://127.0.0.1:4329 --from "$DRILL_FROM" --to "$DRILL_TO" --event-type network_connection_denied --dry-run)
    python3 - "$audit/intent.json" "$DRILL_OPERATOR" "$DRILL_CHANGE" "$DRILL_FROM" "$DRILL_TO" "$head" "$dry" <<'PY'
import json, os, sys, datetime, uuid
path, operator, change, start, end, head, dry = sys.argv[1:]
record = {"schema_version": 1, "operation_id": str(uuid.uuid4()), "record_type": "intent", "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "operator": operator, "change_reference": change, "command": "archive replay --from --to --event-type network_connection_denied",
          "from": start, "to": end, "target_collector": "ws6-linux-replay", "archive_verification": json.loads(head), "dry_run": json.loads(dry)}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as target:
    json.dump(record, target, sort_keys=True); target.flush(); os.fsync(target.fileno())
PY
    rc=0
    out=$(BOWER_INGEST_TOKEN=$(cat /etc/bower/secrets/ingest-token) /opt/bower-cli/bower archive replay --archive /var/lib/bower/archive --collector-url http://127.0.0.1:4329 --from "$DRILL_FROM" --to "$DRILL_TO" --event-type network_connection_denied) || rc=$?
    python3 - "$audit/outcome.json" "$rc" "$out" <<'PY'
import json, os, sys, datetime
path, rc, out = sys.argv[1:]
record = {"schema_version": 1, "record_type": "outcome", "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "cli_exit_code": int(rc), "cli_summary": json.loads(out) if out else None, "delivery_verified": False}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as target:
    json.dump(record, target, sort_keys=True); target.flush(); os.fsync(target.fileno())
PY
    echo "intent: $(cat $audit/intent.json)"; echo "outcome: $(cat $audit/outcome.json)"
    sleep 20
    token=$(cat /etc/bower/secrets/ingest-token)
    curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:4329/v1/status | python3 -c 'import json,sys; q=json.load(sys.stdin)["queue"]; print(json.dumps(q))' ;;
  stop-replay-collector) systemctl stop bower-replay; echo "replay collector stopped $(now)" ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
