#!/bin/bash
set -euo pipefail
umask 077
# Two sources run this script concurrently: aggregate targets 1k and 5k EPS.
# Preserve both reports even when saturation causes non-2xx responses.
result=0
python3 /opt/bower-lab/load.py --phase load1k --rate 500 --seconds 60 || result=1
sleep 10
python3 /opt/bower-lab/load.py --phase load5k --rate 2500 --seconds 60 || result=1
exit "$result"
