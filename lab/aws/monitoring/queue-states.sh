#!/bin/bash
# Queue metadata only (states, attempts, next attempt, failure codes); never payloads.
set -euo pipefail
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select state, count(*), max(delivery_attempts), min(next_attempt_at), max(next_attempt_at), group_concat(distinct last_failure_code) from queue_events_v5 group by state;"
ls -l /var/lib/bower/queue.db* | awk '{print $5, $NF}'
journalctl -u bower --no-pager -o cat --since "-6min" | cut -c1-200 | sort | uniq -c | sort -rn | head -8
