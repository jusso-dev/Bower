#!/bin/bash
# Kernel deny lines (native source) since setup, and rsyslog's forwarding queue state. Counts only.
set -euo pipefail
echo "kernel_deny_lines $(journalctl -k --no-pager -o cat --since '2026-10-31 08:30:00' | grep -c 'BOWER_DENY')"
echo "kernel_first $(journalctl -k --no-pager -o short-iso --since '2026-10-31 08:30:00' | grep 'BOWER_DENY' | head -1 | cut -d' ' -f1)"
echo "kernel_last $(journalctl -k --no-pager -o short-iso --since '2026-10-31 08:30:00' | grep 'BOWER_DENY' | tail -1 | cut -d' ' -f1)"
ls -l /var/lib/rsyslog/ 2>/dev/null | grep -c bower-firewall || true
journalctl -u rsyslog --no-pager -o cat --since '2026-10-31 08:30:00' | grep -ci 'imjournal.*rate\|ratelimit\|lost' || true
