#!/bin/bash
set -euo pipefail
unit="bower-sender-{{STREAM}}"
if systemctl list-units --all --no-legend "$unit.service" | grep -q .; then echo "stream already used"; exit 1; fi
systemd-run --unit="$unit" --property=Restart=no python3 /opt/bower-lab/sender.py --stream '{{STREAM}}' --target '{{TARGET}}' --rate {{RATE}} --start {{START}} --count {{COUNT}} --base '{{BASE}}'
sleep 3
systemctl is-active "$unit"
cat /var/lib/bower-sender/{{STREAM}}.json 2>/dev/null || true
