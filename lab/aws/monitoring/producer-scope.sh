#!/bin/bash
# Authorises the shared ingest token ("default" producer) for the synthetic ws6-drill/lab identity only.
set -euo pipefail
cat > /etc/bower/producer-scopes.json <<'JSON'
[{"producer": "default", "application": {"name": "ws6-drill", "environment": "lab"}}]
JSON
chown root:bower /etc/bower/producer-scopes.json; chmod 0640 /etc/bower/producer-scopes.json
sed -i '/^BOWER_PRODUCER_SCOPES_FILE=/d' /etc/bower/bower.env
echo 'BOWER_PRODUCER_SCOPES_FILE=/etc/bower/producer-scopes.json' >> /etc/bower/bower.env
systemctl restart bower
for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4319/health >/dev/null 2>&1 && break; sleep 1; done
echo "configured $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) $(systemctl is-active bower)"
