#!/bin/bash
# Recovery for a queue that reached its physical page limit: raise BOWER_QUEUE_MAX_BYTES (the
# page limit follows it) and restart. Never deletes or resets queue rows.
set -euo pipefail
: "${DRILL_CAP:?}"
sed -i "s/^BOWER_QUEUE_MAX_BYTES=.*/BOWER_QUEUE_MAX_BYTES=$DRILL_CAP/" /etc/bower/bower.env
systemctl restart bower
echo "recovery $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) cap=$DRILL_CAP restarted"
for i in $(seq 1 90); do
  token=$(cat /etc/bower/secrets/ingest-token)
  undelivered=$(curl -fsS -m 3 -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status 2>/dev/null | python3 -c 'import json,sys; q=json.load(sys.stdin)["queue"]; print(q["queued"]+q["retrying"]+q["uploading"])' 2>/dev/null || echo -1)
  if [ "$undelivered" -ge 0 ] && [ "$undelivered" -le 5 ]; then echo "drained $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) undelivered=$undelivered"; break; fi
  sleep 2
done
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select state, count(*) from queue_events_v5 group by state;" | paste -sd' '
