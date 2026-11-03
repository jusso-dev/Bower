#!/bin/bash
# Owned disposable sender only: install a reviewed helper revision from this run's sender
# artifact prefix (SHA-256 pinned), build rsyslog 8.2610.0 with omrelp into /usr/local and
# restart rsyslog on it. Configuration, queue files and imjournal state are kept. Run it
# between scenarios, never during generation. Prints metadata only.
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}" "${BOWER_TOOL_SHA256:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-(fw|soak|resoak)-[0-9]{8}-[0-9]{6}$ && "$BOWER_TOOL_SHA256" =~ ^[0-9a-f]{64}$ ]]
[ "$(id -u)" = 0 ]
python3 -c 'import json,os,sys; sys.exit(json.load(open("/var/lib/bower-lab/qualification-owner.json")) != {"runId": os.environ["BOWER_LAB_RUN"], "role": "sender"})'
[ "$(aws sts get-caller-identity --query Account --output text)" = 959038055523 ]
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/qualification/$BOWER_LAB_RUN/sender/syslog-host.py.next" "$stage/syslog-host.py"
echo "$BOWER_TOOL_SHA256  $stage/syslog-host.py" | sha256sum --check --strict --quiet
install -m 0755 "$stage/syslog-host.py" /opt/bower-lab/syslog-host.py
BOWER_LAB_HOST=SenderR python3 /opt/bower-lab/syslog-host.py install-rsyslog-source > "$stage/build.json"
/usr/local/sbin/rsyslogd -N1 > "$stage/check.txt" 2>&1 || { tail -20 "$stage/check.txt"; exit 1; }
systemctl restart rsyslog
python3 - "$stage/build.json" <<'PY'
import json, subprocess, sys
build = json.load(open(sys.argv[1]))
show = lambda prop: subprocess.run(["systemctl", "show", "rsyslog", "--property=" + prop, "--value"],
                                   capture_output=True, text=True).stdout.strip()
build.update(active=show("ActiveState"), mainPid=show("MainPID"),
             execStart=show("ExecStart").split(";")[0].replace("{ path=", "").strip())
print(json.dumps(build))
PY
