#!/bin/bash
set -euo pipefail
# Schedule recovery before stopping the relay, so an SSM disconnect cannot strand it.
systemd-run --unit=bower-lab-relay-recover --on-active=45s /usr/bin/systemctl start bower >/dev/null
systemctl stop bower
python3 - <<'PY'
import json,time
print(json.dumps({'phase':'relay-outage','stoppedAt':time.time(),'scheduledRecoverySeconds':45}))
PY
