#!/bin/bash
# Native kernel deny lines vs accepted firewall events by source timestamp before DRILL_CUTOFF.
set -euo pipefail
: "${DRILL_CUTOFF:?}"
native=$(journalctl -k --no-pager -o short-iso-precise --since '2026-10-31 08:30:00' --until "$DRILL_CUTOFF" | grep -c 'BOWER_DENY')
accepted=$(sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select count(distinct event_id) from queue_events_v5 where json_extract(payload,'$.eventType')='network_connection_denied' and json_extract(payload,'$.timeGenerated') < '${DRILL_CUTOFF/ /T}';")
echo "native=$native accepted=$accepted missing=$((native-accepted)) cutoff=$DRILL_CUTOFF"
for window in "08:30:00 09:00:00" "09:00:00 09:10:00" "09:10:00 09:12:00" "09:12:00 09:20:00" "09:20:00 09:40:00" "09:40:00 10:00:00" "10:00:00 10:20:00"; do
  set -- $window
  n=$(journalctl -k --no-pager -o cat --since "2026-10-31 $1" --until "2026-10-31 $2" | grep -c 'BOWER_DENY' || true)
  a=$(sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select count(distinct event_id) from queue_events_v5 where json_extract(payload,'$.eventType')='network_connection_denied' and json_extract(payload,'$.timeGenerated') >= '2026-10-31T$1' and json_extract(payload,'$.timeGenerated') < '2026-10-31T$2';")
  echo "window $1-$2 native=$n accepted=$a"
done
