#!/bin/bash
# Replaces the collector binaries and health check with the bucket's current build; keeps the
# queue, configuration and secrets. Prints hashes only.
set -euo pipefail
trap 'echo "upgrade-linux failed at line $LINENO" >&2' ERR
stage=$(mktemp -d)
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/collector.tar.gz" "$stage/"
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/bower-healthcheck.py" /opt/bower/monitoring/bower-healthcheck.py
systemctl stop bower
find /opt/bower -mindepth 1 -maxdepth 1 ! -name monitoring -exec rm -rf {} +
tar -xzf "$stage/collector.tar.gz" -C /opt/bower --strip-components=1
chmod 0755 /opt/bower/Bower.Collector /opt/bower/monitoring/*.py
rm -rf "$stage"
systemctl start bower
for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:4319/health >/dev/null 2>&1 && break; sleep 1; done
echo "upgraded $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) $(systemctl is-active bower)"
sha256sum /opt/bower/Bower.Collector.dll /opt/bower/monitoring/bower-healthcheck.py | sed 's|  | |'
