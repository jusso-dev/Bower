# SSM entry point for syslog-host.py (see syslog-lab.py). Public arguments only.
set -euo pipefail
tool=/opt/bower-lab/syslog-host.py
if [ "${BOWER_STEP:-run}" = "fetch" ]; then
  install -d -m 0755 /opt/bower-lab
  aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/syslog-host.py" "$tool.new" --only-show-errors
  echo "$BOWER_TOOL_SHA256  $tool.new" | sha256sum --check --strict --quiet
  install -m 0755 "$tool.new" "$tool" && rm -f "$tool.new"
  echo "tool $BOWER_TOOL_SHA256"
fi
[ -n "${BOWER_ARGS:-}" ] || exit 0
if [ -n "${BOWER_UNIT:-}" ]; then
  # Long-running steps continue after the SSM command returns; results land in /var/lib/bower-lab/results.
  systemd-run --unit "bower-lab-$BOWER_UNIT" --collect \
    --setenv=BOWER_LAB_RUN="$BOWER_LAB_RUN" --setenv=BOWER_LAB_BUCKET="$BOWER_LAB_BUCKET" \
    --setenv=BOWER_LAB_HOST="$BOWER_LAB_HOST" --setenv=AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
    /usr/bin/python3 "$tool" $BOWER_ARGS
else
  /usr/bin/python3 "$tool" $BOWER_ARGS
fi
