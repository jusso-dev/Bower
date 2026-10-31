#!/bin/bash
# Runs one storage-pressure scenario on the Linux collector through storage-lab.py.
# The driver comes from this run's checksummed artifacts; results are metadata only.
set -euo pipefail
trap 'echo "failed at line $LINENO" >&2' ERR
: "${BOWER_LAB_RUN:?}" "${BOWER_LAB_BUCKET:?}" "${BOWER_SCENARIO:?}"
[[ "$BOWER_SCENARIO" =~ ^(smoke|queue-cap|watermarks|disk-full|reconcile|probe)$ ]]
artifacts=/root/ws3-artifacts
mkdir -p "$artifacts"
aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/artifacts/linux/SHA256SUMS" "$artifacts/SHA256SUMS"
for file in $(awk '{print $2}' "$artifacts/SHA256SUMS"); do
  aws s3 cp --quiet "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/artifacts/linux/$file" "$artifacts/$file"
done
(cd "$artifacts" && sha256sum -c --quiet SHA256SUMS)
python3 "$artifacts/storage-linux-driver.py" "$BOWER_SCENARIO" --rate "${BOWER_RATE:-100}" \
  --hold "${BOWER_HOLD:-120}" --limit "${BOWER_LIMIT:-3600}" | tee "/var/log/ws3/$BOWER_SCENARIO-stdout.json"
for file in /var/log/ws3/"$BOWER_SCENARIO"*; do
  aws s3 cp --quiet "$file" "s3://$BOWER_LAB_BUCKET/$BOWER_LAB_RUN/results/linux/$(basename "$file")"
done
