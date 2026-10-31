#!/bin/bash
# Queue file page accounting (metadata only).
set -euo pipefail
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "pragma page_size; pragma page_count; pragma freelist_count;" | paste -sd' '
sqlite3 -readonly "file:/var/lib/bower/queue.db?mode=ro" "select name, count(*) from sqlite_master where type in ('table','index') group by type;" | paste -sd' '
grep '^BOWER_QUEUE_MAX_BYTES' /etc/bower/bower.env
journalctl -u bower --no-pager -o cat --since "-15min" | grep -c "Delivery loop failed with SqliteException" || true
