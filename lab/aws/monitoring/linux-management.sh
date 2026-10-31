#!/bin/bash
# Drill only: runs the management API with development authentication on loopback (it refuses
# that mode outside Development), enrols the Linux collector with a one-time token and approves it.
# The token is created and consumed on the host and never printed.
set -euo pipefail
trap 'echo "linux-management failed at line $LINENO" >&2' ERR
umask 077
stage=$(mktemp -d)
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/management.tar.gz" "$stage/"
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/bower-fleet-check.py" /opt/bower/monitoring/bower-fleet-check.py
chmod 0755 /opt/bower/monitoring/bower-fleet-check.py
install -d -m 0755 /opt/bower-management
tar -xzf "$stage/management.tar.gz" -C /opt/bower-management --strip-components=1
rm -rf "$stage"
cat > /etc/systemd/system/bower-management-dev.service <<'UNIT'
[Unit]
Description=Bower management API (drill: development authentication, loopback only)
[Service]
ExecStart=/opt/bower-management/Bower.Management.Api
DynamicUser=yes
StateDirectory=bower-management
WorkingDirectory=/opt/bower-management
Environment=ASPNETCORE_ENVIRONMENT=Development BOWER_AUTH_MODE=development
Environment=BOWER_MANAGEMENT_LISTEN_URL=http://127.0.0.1:4320
Environment=BOWER_MANAGEMENT_DB_PATH=/var/lib/bower-management/management.db
Restart=on-failure
UNIT
systemctl daemon-reload
systemctl restart bower-management-dev
for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4320/health >/dev/null 2>&1 && break; sleep 1; done
api=http://127.0.0.1:4320/api
install -d -m 0700 -o bower -g bower /var/lib/bower/enrolment
curl -fsS -m 10 -H 'Content-Type: application/json' -d '{"environment":"lab","reason":"ws6 monitoring drill","collectorId":"ws6-linux-01","expiresInHours":2}' "$api/enrolment-tokens" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"], end="")' > /var/lib/bower/enrolment/enrolment-token
chown bower:bower /var/lib/bower/enrolment/enrolment-token; chmod 0600 /var/lib/bower/enrolment/enrolment-token
sed -i '/^BOWER_MANAGEMENT_/d' /etc/bower/bower.env
cat >> /etc/bower/bower.env <<'ENV'
BOWER_MANAGEMENT_ENDPOINT=http://127.0.0.1:4320/
BOWER_MANAGEMENT_AUTH=enrolment
BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE=/var/lib/bower/enrolment/enrolment-token
BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE=true
ENV
systemctl restart bower
for i in $(seq 1 60); do
  pending=$(curl -fsS -m 5 "$api/approvals" | python3 -c 'import json,sys; print(sum(1 for a in json.load(sys.stdin) if a.get("collectorId")=="ws6-linux-01"))' 2>/dev/null || echo 0)
  [ "$pending" -gt 0 ] && break; sleep 2
done
curl -fsS -m 10 -H 'Content-Type: application/json' -H 'X-Bower-Development-Person: reviewer' -d '{"reason":"ws6 monitoring drill"}' "$api/approvals/ws6-linux-01/approve" >/dev/null
sleep 75
python3 /opt/bower/monitoring/bower-fleet-check.py --url http://127.0.0.1:4320 --format json || true
