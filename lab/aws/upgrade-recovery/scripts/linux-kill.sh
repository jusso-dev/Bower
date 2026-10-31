#!/bin/bash
# SIGKILL the collector under load (optionally right after restoring the destination).
set -euo pipefail
if [ '{{UNBLOCK}}' = yes ]; then nft delete table inet bower_ws4_outage 2>/dev/null || true; sleep {{DELAY}}; fi
pid=$(systemctl show bower --property=MainPID --value)
killed=$(date -u +%s.%N); kill -9 "$pid"
for i in $(seq 1 120); do newpid=$(systemctl show bower --property=MainPID --value); if [ "$newpid" != 0 ] && [ "$newpid" != "$pid" ] && curl -fsS -o /dev/null http://127.0.0.1:4319/health; then break; fi; sleep 0.5; done
ready=$(date -u +%s.%N)
echo "{\"label\":\"{{LABEL}}\",\"killedPid\":$pid,\"newPid\":$newpid,\"killedAt\":$killed,\"healthyAt\":$ready,\"recoverySeconds\":$(python3 -c "print(round($ready-$killed,2))"),\"unblocked\":\"{{UNBLOCK}}\"}"
