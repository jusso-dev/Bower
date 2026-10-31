#!/bin/bash
# rsyslog forwarding queue and action state (metadata only).
ls -l /var/lib/rsyslog/ | awk 'NR>1 {print $5, $NF}'
journalctl -u rsyslog --no-pager -o short-iso --since '2026-10-31 08:30:00' | grep -iE 'suspend|resum|queue|disk|error' | cut -c1-220 | tail -15
token=$(cat /etc/bower/secrets/ingest-token)
curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; s=json.load(sys.stdin); print(json.dumps([{k:l[k] for k in ("activeConnections","connectionsAccepted","framesReceived","queued","retries","lastFrameAt")} for l in s["syslog"]]), s["intake"]["observedSince"])'
