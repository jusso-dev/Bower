#!/bin/bash
# Management fleet check (development API on loopback) and the host check, metadata only.
python3 /opt/bower/monitoring/bower-fleet-check.py --url http://127.0.0.1:4320 --format json; echo "fleet-exit $?"
journalctl -u bower-healthcheck --no-pager -o short-iso -n 6 | grep "healthcheck\[" | tail -2
