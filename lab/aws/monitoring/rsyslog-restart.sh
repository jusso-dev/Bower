#!/bin/bash
# Restarts the lab sender so it reloads its disk-assisted queue; reports counts only.
set -euo pipefail
token=$(cat /etc/bower/secrets/ingest-token)
frames() { curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["syslog"][0]["framesReceived"])'; }
before=$(frames); echo "before frames=$before queue=$(stat -c %s /var/lib/rsyslog/bower-firewall.00000001 2>/dev/null || echo none) $(date -u +%H:%M:%S)"
systemctl restart rsyslog
sleep 90
after=$(frames); echo "after frames=$after delta=$((after-before)) queue=$(ls /var/lib/rsyslog | grep bower-firewall | tr '\n' ' ') $(date -u +%H:%M:%S)"
