#!/bin/bash
# Refreshes the health-check script from the run's bucket.
set -euo pipefail
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/artifacts/linux/bower-healthcheck.py" /opt/bower/monitoring/bower-healthcheck.py
chmod 0755 /opt/bower/monitoring/bower-healthcheck.py
sha256sum /opt/bower/monitoring/bower-healthcheck.py
