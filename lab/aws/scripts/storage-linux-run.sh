#!/bin/bash
# Runs one storage-pressure scenario on the Linux collector through storage-lab.py.
# The driver comes from this run's checksummed artifacts; results are metadata only.
set -euo pipefail
: "${BOWER_LAB_RUN:?}" "${BOWER_LAB_BUCKET:?}" "${BOWER_SCENARIO:?}"
[[ "$BOWER_SCENARIO" =~ ^(queue-cap|watermarks|disk-full|reconcile|probe)$ ]]
artifacts=/root/ws3-artifacts
aws s3 cp --quiet --recursive "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/artifacts/linux/" "$artifacts/"
(cd "$artifacts" && sha256sum -c --quiet SHA256SUMS)
python3 "$artifacts/storage-linux-driver.py" "$BOWER_SCENARIO" --rate "${BOWER_RATE:-100}" \
  --hold "${BOWER_HOLD:-120}" --limit "${BOWER_LIMIT:-3600}" | tee "/var/log/ws3/$BOWER_SCENARIO-stdout.json"
for file in /var/log/ws3/"$BOWER_SCENARIO"*; do
  aws s3 cp --quiet "$file" "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/results/linux/$(basename "$file")"
done
