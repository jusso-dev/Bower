#!/bin/bash
# Owned disposable collector only: set BOWER_QUEUE_MAX_BYTES just above the queue's current
# size so the queue-capacity scenario reaches the physical page limit (about cap + 4 MiB)
# after BOWER_CAP_HEADROOM_MIB more MiB. Never deletes or resets queue rows. Recovery is the
# scenario's raise-cap step (or monitoring/raise-cap.sh), which restores the default cap.
set -euo pipefail
umask 077
: "${BOWER_LAB_RUN:?}" "${BOWER_CAP_HEADROOM_MIB:?}"
python3 - <<'PY'
import json
import os
from pathlib import Path
import re
import subprocess

run = os.environ["BOWER_LAB_RUN"]
headroom = int(os.environ["BOWER_CAP_HEADROOM_MIB"])
if (os.geteuid() != 0 or not re.fullmatch(r"bower-fw-\d{8}-\d{6}", run) or not 8 <= headroom <= 256
        or json.loads(Path("/var/lib/bower-lab/qualification-owner.json").read_text()) != {"runId": run, "role": "collector"}):
    raise SystemExit("queue-cap: not an owned collector or invalid headroom")
queue = Path("/var/lib/bower/queue.db")
size = sum(path.stat().st_size for path in (queue, Path(str(queue) + "-wal")) if path.exists())
cap = max(16 * 1024 * 1024, size + headroom * 1024 * 1024)
env = Path("/etc/bower/bower.env")
text = re.sub(r"^BOWER_QUEUE_MAX_BYTES=\d+\n", "", env.read_text(), flags=re.M)
env.write_text(text + "BOWER_QUEUE_MAX_BYTES={}\n".format(cap))
subprocess.run(["systemctl", "restart", "bower.service"], check=True, timeout=120)
active = subprocess.run(["systemctl", "is-active", "bower.service"], capture_output=True, text=True).stdout.strip()
print(json.dumps({"queueBytesBefore": size, "queueMaxBytes": cap, "headroomMiB": headroom, "active": active}))
PY
