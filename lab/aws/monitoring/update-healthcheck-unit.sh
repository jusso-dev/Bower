#!/bin/bash
set -euo pipefail
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/bower-healthcheck.service" /etc/systemd/system/bower-healthcheck.service
grep -q '^BOWER_QUEUE_PATH=' /etc/bower/bower.env || echo 'BOWER_QUEUE_PATH=/var/lib/bower/queue.db' >> /etc/bower/bower.env
systemctl daemon-reload
systemctl start bower-healthcheck.service || true
journalctl -u bower-healthcheck --no-pager -o short-iso -n 3 | grep "healthcheck\[" || true
