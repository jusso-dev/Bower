#!/bin/bash
# Drill D7 on the Linux collector. DRILL_ACTION=poison posts synthetic events whose attributes
# exceed the 64 KiB Logs Ingestion column limit (the output preflight dead-letters them instead
# of letting Azure truncate them). DRILL_ACTION=replay runs the audited offline replay of the
# reviewed dead-lettered IDs. Metadata only: event ids, codes, counts and audit records.
set -euo pipefail
: "${DRILL_ACTION:?}"
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
db=/var/lib/bower/queue.db
cli=/opt/bower-cli/bower
case "$DRILL_ACTION" in
  poison)
    python3 - <<'PY'
import json, urllib.request, uuid, datetime
from pathlib import Path

# Never forward the bearer token to a redirected destination.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect())
token = Path("/etc/bower/secrets/ingest-token").read_text().strip()
for index in range(int(3)):
    event_id = "ws6-poison-" + uuid.uuid4().hex[:20]
    words = ("synthetic drill padding " * 700)[:15000]
    event = {"schemaVersion": "1.0.0", "eventId": event_id, "timeGenerated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "eventCategory": "authentication", "eventType": "authentication_failure", "eventAction": "authentication.attempt",
             "eventResult": "failure", "eventSeverity": "low", "eventOutcomeReason": "Synthetic ws6 drill",
             "application": {"name": "ws6-drill", "environment": "lab"}, "actor": {"username": "ws6-synthetic-user"},
             "request": {"correlationId": event_id},
             "attributes": {f"padding{part}": words for part in range(5)}}
    request = urllib.request.Request("http://127.0.0.1:4319/v1/events", data=json.dumps(event).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=10) as response:
            print("posted", event_id, response.status)
    except urllib.error.HTTPError as error:
        # A refusal or redirect is not an accepted drill event. Do not print the
        # response body or mark the phase complete.
        raise SystemExit(f"Synthetic drill ingestion failed with HTTP {error.code}") from None
PY
    echo "fault $(now) poison events posted" ;;
  list)
    systemctl stop bower
    "$cli" queue dead-letters --database "$db" --max 100 | python3 -c 'import json,sys; [print(r.get("eventId"), r.get("lastFailureCode") or r.get("failureCode"), r.get("deliveryAttempts")) for r in json.load(sys.stdin)]'
    systemctl start bower ;;
  replay)
    : "${DRILL_EVENTS:?}"
    install -d -m 0700 /var/lib/bower-audit
    systemctl stop bower
    echo "stopped $(now)"
    args=()
    for id in $DRILL_EVENTS; do args+=(--event "$id"); done
    rc=0
    python3 /opt/bower/monitoring/replay.py --cli "$cli" --database "$db" \
      --audit-directory "/var/lib/bower-audit/${DRILL_CHANGE:?}" --operator "${DRILL_OPERATOR:?}" \
      --change-reference "$DRILL_CHANGE" "${args[@]}" || rc=$?
    echo "replay-exit $rc $(now)"
    for record in intent outcome; do echo "$record: $(cat /var/lib/bower-audit/$DRILL_CHANGE/$record.json)"; done
    ls -l "/var/lib/bower-audit/$DRILL_CHANGE" | awk 'NR>1 {print $1, $NF}'
    sqlite3 -readonly "file:$db?mode=ro" "select state, count(*) from queue_events_v5 where event_id like 'ws6-poison-%' group by state;" | paste -sd' '
    systemctl start bower
    for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4319/health >/dev/null 2>&1 && break; sleep 1; done
    echo "started $(now)"
    sleep 20
    sqlite3 -readonly "file:$db?mode=ro" "select event_id, state, last_failure_code, delivery_attempts from queue_events_v5 where event_id like 'ws6-poison-%';"
    "$cli" queue verify --database "$db" | tail -2 ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
