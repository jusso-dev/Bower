#!/bin/bash
# Read-only sender diagnostic: rsyslog's own service messages (no event content) around
# the previous boot's shutdown and this boot's start, plus queue file and imjournal state metadata.
set -euo pipefail
echo "== boots"; journalctl --list-boots --no-pager | tail -3
echo "== rsyslog unit, previous boot (last 40)"
journalctl -b -1 -u rsyslog --no-pager -o short-iso-precise | grep -v "BOWER_DENY" | tail -40
echo "== rsyslog unit, this boot (first 25)"
journalctl -b 0 -u rsyslog --no-pager -o short-iso-precise | grep -v "BOWER_DENY" | head -25
echo "== rsyslog work directory"; ls -la --time-style=full-iso /var/lib/rsyslog/ | grep -v "^total"
echo "== rsyslog version"; rsyslogd -v | head -2
