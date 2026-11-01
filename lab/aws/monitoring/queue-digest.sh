#!/bin/bash
# Accepted firewall event identities in the local queue up to DRILL_CUTOFF (all states): count
# and SHA-256 of the sorted ids joined by newlines. Identities only; payloads are never printed.
set -euo pipefail
: "${DRILL_CUTOFF:?}"
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select event_id from queue_events_v5 where json_extract(payload,'$.eventType')='network_connection_denied' and received_at < '$DRILL_CUTOFF';" > /tmp/ws6-ids.txt
python3 -c 'import hashlib; ids=sorted(set(open("/tmp/ws6-ids.txt").read().split())); print("queue_ids", len(ids), hashlib.sha256("\n".join(ids).encode()).hexdigest())'
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select state, count(*) from queue_events_v5 where json_extract(payload,'$.eventType')='network_connection_denied' and received_at < '$DRILL_CUTOFF' group by state;" | paste -sd' '
rm -f /tmp/ws6-ids.txt
