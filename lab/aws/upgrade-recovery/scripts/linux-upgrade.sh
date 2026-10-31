#!/bin/bash
# In-place package change under load. Prints metadata only.
set -euo pipefail
before_pkg=$(rpm -q bower-collector); before_pid=$(systemctl show bower --property=MainPID --value)
start=$(date -u +%s.%N)
dnf {{VERB}} -y {{PACKAGE}} >/var/log/bower-lab-upgrade-{{LABEL}}.log 2>&1; rc=$?
end=$(date -u +%s.%N)
for i in $(seq 1 60); do systemctl is-active --quiet bower && curl -fsS -o /dev/null http://127.0.0.1:4319/health && break; sleep 1; done
ready=$(date -u +%s.%N)
python3 - "$before_pkg" "$before_pid" "$start" "$end" "$ready" "$rc" <<'PY'
import json, subprocess, sys
pkg, pid, start, end, ready, rc = sys.argv[1:]
run = lambda *a: subprocess.run(a, capture_output=True, text=True).stdout.strip()
print(json.dumps({'label': '{{LABEL}}', 'before': pkg, 'after': run('rpm', '-q', 'bower-collector'), 'dnfExit': int(rc),
  'beforePid': pid, 'afterPid': run('systemctl', 'show', 'bower', '--property=MainPID', '--value'),
  'packageSeconds': round(float(end) - float(start), 2), 'healthySecondsAfterPackage': round(float(ready) - float(end), 2),
  'active': run('systemctl', 'is-active', 'bower'), 'envFileUntouched': run('rpm', '-V', 'bower-collector') ,
  'startedAt': start, 'finishedAt': ready}))
PY
